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

  // простая проверка ключа: из заголовка x-auth или из ?key=
  const url = new URL(req.url);
  const provided = req.headers.get('x-auth') || url.searchParams.get('key') || "";
  if (SECRET && provided !== SECRET) {
    return new Response('forbidden', { status: 403, headers: { 'access-control-allow-origin': '*' } });
  }

  try {
    const ct = (req.headers.get('content-type') || '').toLowerCase();
    let outBody, outHeaders = {};

    if (req.method === 'GET') {
      const payload = Object.fromEntries(url.searchParams);
      delete payload.key; // не отправляем ключ в PA
      outBody = JSON.stringify(payload);
      outHeaders = { 'content-type': 'application/json' };
    } else if (req.method === 'POST') {
      if (ct.includes('application/json')) {
        outBody = await req.text();
        outHeaders = { 'content-type': 'application/json' };
      } else if (ct.includes('application/x-www-form-urlencoded')) {
        const raw = await req.text();
        const params = new URLSearchParams(raw);
        outBody = JSON.stringify(Object.fromEntries(params));
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
