import { clearSession, originAllowed, send } from './_common.js';

export default function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Método no permitido' });
  if (!originAllowed(req)) return send(res, 403, { error: 'Origen no permitido' });
  clearSession(res);
  return send(res, 200, { ok: true });
}
