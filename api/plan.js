import {
  adminRequest,
  authorize,
  configured,
  originAllowed,
  privateUrl,
  send
} from './_common.js';

async function verifyAccess(req, res) {
  const user = await authorize(req, res);

  if (!user?.id) {
    return { error: send(res, 401, { error: 'Iniciá sesión para continuar' }) };
  }

  const access = await adminRequest(
    `/rest/v1/program_access?select=user_id&user_id=eq.${encodeURIComponent(user.id)}&program_slug=eq.plan-60-dias&active=eq.true&limit=1`
  );

  if (!access.ok) throw new Error('Error de permisos');

  const rows = await access.json();

  if (!rows.length) {
    return {
      error: send(res, 403, {
        error: 'Tu cuenta todavía no tiene habilitado este programa. Escribime por WhatsApp.'
      })
    };
  }

  return { user };
}

async function createPlanUrl() {
  const signed = await adminRequest(
    '/storage/v1/object/sign/rfl-private/plan-60-dias.html',
    {
      method: 'POST',
      body: JSON.stringify({ expiresIn: 60 })
    }
  );

  if (!signed.ok) throw new Error('Material no disponible');

  const { signedURL, signedUrl } = await signed.json();
  return privateUrl(signedURL || signedUrl);
}

export default async function handler(req, res) {
  if (!['GET', 'POST'].includes(req.method)) {
    return send(res, 405, { error: 'Método no permitido' });
  }

  if (req.method === 'POST' && !originAllowed(req)) {
    return send(res, 403, { error: 'Origen no permitido' });
  }

  if (!configured) {
    return send(res, 503, { error: 'Configuración pendiente' });
  }

  try {
    const access = await verifyAccess(req, res);
    if (access.error) return access.error;

    if (req.method === 'POST') {
      return send(res, 200, { url: '/api/plan?view=1' });
    }

    const planUrl = await createPlanUrl();
    const plan = await fetch(planUrl);

    if (!plan.ok) throw new Error('No se pudo descargar el plan');

    const html = await plan.text();

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'private, no-store');
    return res.status(200).send(html);
  } catch {
    return send(res, 502, {
      error: 'No se pudo abrir el plan. Intentá más tarde.'
    });
  }
}
