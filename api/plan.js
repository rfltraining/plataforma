import { adminRequest, authorize, configured, originAllowed, privateUrl, send } from './_common.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Método no permitido' });
  if (!originAllowed(req)) return send(res, 403, { error: 'Origen no permitido' });
  if (!configured) return send(res, 503, { error: 'Configuración pendiente' });
  try {
    const user = await authorize(req, res);
    if (!user?.id) return send(res, 401, { error: 'Iniciá sesión para continuar' });
    const access = await adminRequest(`/rest/v1/program_access?select=user_id&user_id=eq.${encodeURIComponent(user.id)}&program_slug=eq.plan-60-dias&active=eq.true&limit=1`);
    if (!access.ok) throw new Error('Error de permisos');
    const rows = await access.json();
    if (!rows.length) return send(res, 403, { error: 'Tu cuenta todavía no tiene habilitado este programa. Escribime por WhatsApp.' });
    const signed = await adminRequest('/storage/v1/object/sign/rfl-private/plan-60-dias.html', {
      method: 'POST', body: JSON.stringify({ expiresIn: 60 }),
    });
    if (!signed.ok) throw new Error('Material no disponible');
    const { signedURL, signedUrl } = await signed.json();
    return send(res, 200, { url: privateUrl(signedURL || signedUrl) });
  } catch { return send(res, 502, { error: 'No se pudo abrir el plan. Intentá más tarde.' }); }
}
