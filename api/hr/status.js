export const config = { runtime: 'edge' };

export default async (req) => {
  const FLOW_URL = process.env.FLOW_URL;
  if (!FLOW_URL) return new Response('FLOW_URL is not set', { status: 500 });

  const SECRET = process.env.SECRET_TOKEN || "";

  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-headers': 'content-type,x-auth',
        'access-control-allow-methods': 'GET,POST,OPTIONS',
      },
    });
  }

  // простая защита по ключу (в заголовке x-auth или ?key=)
  const url = new URL(req.url);
  const provided = req.headers.get('x-auth') || url.searchParams.get('key') || "";
  if (SECRET && provided !== SECRET) {
    return new Response('forbidden', { status: 403, headers: { 'access-control-allow-origin': '*' } });
  }

  try {
    const ct = (req.headers.get('content-type') || '').toLowerCase();
    let outBody; let outHeaders = {};

    if (req.method === 'GET') {
      // 1) собираем объект из query
      const payload = Object.fromEntries(url.searchParams);

      // 2) ключ не отправляем в PA
      delete payload.key;

      // 3) авто-парсер: если значение похоже на JSON — парсим
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
      outHeaders = { 'content-type': 'application/json' };

    } else if (req.method === 'POST') {
      if (ct.includes('application/json')) {
        outBody = await req.text();
        outHeaders = { 'content-type': 'application/json' };
      } else if (ct.includes('application/x-www-form-urlencoded')) {
        const raw = await req.text();
        const params = new URLSearchParams(raw);
        const obj = Object.fromEntries(params);
        outBody = JSON.stringify(obj);
        outHeaders = { 'content-type': 'application/json' };
      } else {
        outBody = await req.text();
        outHeaders = { 'content-type': 'application/octet-stream' };
      }
    } else {
      return new Response('method not allowed', { status: 405 });
    }

    const res = await fetch(FLOW_URL, {
      method: 'POST',
      headers: { ...outHeaders, accept: 'application/json, text/plain, */*' },
      body: outBody,
      cache: 'no-store',
    });

    const text = await res.text();
    return new Response(text, {
      status: res.status,
      headers: {
        'access-control-allow-origin': '*',
        'content-type': res.headers.get('content-type') || 'text/plain; charset=utf-8',
      },
    });
  } catch (err) {
    return new Response(`proxy error: ${err instanceof Error ? err.message : String(err)}`, {
      status: 502,
      headers: { 'access-control-allow-origin': '*' },
    });
  }
};
