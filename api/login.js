import { configured, originAllowed, send, setSession } from './_common.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Método no permitido' });
  if (!originAllowed(req)) return send(res, 403, { error: 'Origen no permitido' });
  if (!configured) return send(res, 503, { error: 'Configuración pendiente' });
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string' || email.length > 254 || password.length > 256 || !email.includes('@')) {
    return send(res, 400, { error: 'Ingresá tu correo y contraseña' });
  }
  try {
    const response = await fetch(`${process.env.SUPABASE_URL.replace(/\/$/, '')}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: { apikey: process.env.SUPABASE_PUBLISHABLE_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) return send(res, 401, { error: 'Correo o contraseña incorrectos' });
    const tokens = await response.json();
    setSession(res, tokens);
    return send(res, 200, { ok: true });
  } catch { return send(res, 502, { error: 'No se pudo conectar. Probá de nuevo.' }); }
}
