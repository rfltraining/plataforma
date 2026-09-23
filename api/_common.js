const base = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const publicKey = process.env.SUPABASE_PUBLISHABLE_KEY || '';
const secretKey = process.env.SUPABASE_SECRET_KEY || '';
export const configured = Boolean(base && publicKey && secretKey);

export function send(res, status, body) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json(body);
}

export function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  try { return new URL(origin).host === req.headers.host && new URL(origin).protocol === 'https:'; }
  catch { return false; }
}

export function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split(/=(.*)/s).slice(0, 2)));
}

function cookie(name, value, seconds) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${seconds}`;
}

export function setSession(res, tokens) {
  res.setHeader('Set-Cookie', [
    cookie('rfl_at', tokens.access_token, Math.min(Number(tokens.expires_in) || 3600, 3600)),
    cookie('rfl_rt', tokens.refresh_token, 60 * 60 * 24 * 30),
  ]);
}

export function clearSession(res) {
  res.setHeader('Set-Cookie', [cookie('rfl_at', '', 0), cookie('rfl_rt', '', 0)]);
}

async function authRequest(path, options = {}) {
  return fetch(`${base}/auth/v1/${path}`, {
    ...options,
    headers: { apikey: publicKey, 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
}

export async function authorize(req, res) {
  const c = cookies(req);
  let access = decodeURIComponent(c.rfl_at || '');
  const refresh = decodeURIComponent(c.rfl_rt || '');
  if (!access && !refresh) return null;
  let response = access ? await authRequest('user', { headers: { Authorization: `Bearer ${access}` } }) : null;
  if ((!response || !response.ok) && refresh) {
    const refreshed = await authRequest('token?grant_type=refresh_token', { method: 'POST', body: JSON.stringify({ refresh_token: refresh }) });
    if (!refreshed.ok) return null;
    const tokens = await refreshed.json();
    setSession(res, tokens);
    access = tokens.access_token;
    response = await authRequest('user', { headers: { Authorization: `Bearer ${access}` } });
  }
  return response?.ok ? response.json() : null;
}

export async function adminRequest(path, options = {}) {
  return fetch(`${base}${path}`, {
    ...options,
    headers: {
      apikey: secretKey,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
}

export function privateUrl(signed) {
  if (!signed || typeof signed !== 'string') throw new Error('URL privada no recibida');
  const normalized = signed.startsWith('/object/sign/')
    ? `/storage/v1${signed}`
    : signed;
  const url = new URL(normalized, base);
  if (url.origin !== new URL(base).origin || !url.pathname.startsWith('/storage/v1/object/sign/')) {
    throw new Error('URL privada inválida');
  }
  return url.toString();
}
