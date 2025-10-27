export const config = { runtime: 'edge' };

export default async (req) => {
  const FLOW_URL = process.env.FLOW_URL;
  const SECRET   = process.env.SECRET_TOKEN || '';

  if (!FLOW_URL) {
    return new Response('FLOW_URL is not set', { status: 500, headers: { 'access-control-allow-origin': '*' } });
  }

  // CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-headers': 'content-type,x-auth,x-huntflow-event,x-huntflow-delivery,x-huntflow-signature',
        'access-control-allow-methods': 'GET,POST,OPTIONS',
      },
    });
  }

  // простая защита по ключу (в заголовке x-auth или ?key=)
  const url = new URL(req.url);
  const provided = req.headers.get('x-auth') || url.searchParams.get('key') || '';
  if (SECRET && provided !== SECRET) {
    return new Response('forbidden', { status: 403, headers: { 'access-control-allow-origin': '*' } });
  }

  try {
    const ct = (req.headers.get('content-type') || '').toLowerCase();
    let outBody;
    let outHeaders = {};

    if (req.method === 'GET') {
      // Соберём JSON из query, ключ удалим
      const payload = Object.fromEntries(url.searchParams);
      delete payload.key;

      // Автопарсинг значений, похожих на JSON
      for (const k of Object.keys(payload)) {
        const v = payload[k];
        if (typeof v === 'string') {
          const s = v.trim();
          if ((s.startsWith('{') && s.endsWith('}')) || (s.startsWith('[') && s.endsWith(']'))) {
            try { payload[k] = JSON.parse(s); } catch { /* оставим строкой */ }
          }
        }
      }

      outBody = JSON.stringify(payload);
      outHeaders['content-type'] = 'application/json';

    } else if (req.method === 'POST') {
      if (ct.includes('application/json')) {
        outBody = await req.text();
        outHeaders['content-type'] = 'application/json';
      } else if (ct.includes('application/x-www-form-urlencoded')) {
        const raw = await req.text();
        const params = new URLSearchParams(raw);
        const obj = Object.fromEntries(params);
        outBody = JSON.stringify(obj);
        outHeaders['content-type'] = 'application/json';
      } else {
        // двоичные/текстовые данные пересылаем как есть
        outBody = await req.text();
        outHeaders['content-type'] = ct || 'application/octet-stream';
      }
    } else {
      return new Response('method not allowed', { status: 405, headers: { 'access-control-allow-origin': '*' } });
    }

    // Пробросим нужные заголовки (например, Huntflow)
    const passThrough = {};
    for (const [k, v] of req.headers.entries()) {
      if (k.startsWith('x-huntflow-')) {
        passThrough[k] = v;
      }
    }

    const res = await fetch(FLOW_URL, {
      method: 'POST',
      headers: { ...outHeaders, ...passThrough },
      body: outBody
    });

    const text = await res.text();
    return new Response(text, {
      status: res.status,
      headers: { 'access-control-allow-origin': '*' }
    });

  } catch (e) {
    return new Response(`proxy error: ${e?.message || e}`, {
      status: 500,
      headers: { 'access-control-allow-origin': '*' }
    });
  }
};
