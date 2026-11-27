function decodeBase64Url(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const raw = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function validAdminSession(request) {
  try {
    const secret = Netlify.env.get("SESSION_SECRET") || "";
    const username = Netlify.env.get("ADMIN_USER") || Netlify.env.get("ADMIN_USERNAME") || "";
    if (!secret || !username) return false;

    const cookieHeader = request.headers.get("cookie") || "";
    const token = cookieHeader.split(";")
      .map(part => part.trim())
      .find(part => part.startsWith("blackmaps_admin="))
      ?.slice("blackmaps_admin=".length);
    if (!token) return false;

    const [payload, signature, extra] = token.split(".");
    if (!payload || !signature || extra !== undefined) return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const expected = encodeBase64Url(new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))
    ));

    const a = new TextEncoder().encode(signature);
    const b = new TextEncoder().encode(expected);
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    if (diff !== 0) return false;

    const session = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)));
    return session.sub === username && Number.isFinite(session.exp) && session.exp > Date.now();
  } catch {
    return false;
  }
}

export default async function handler(request, context) {
  const headers = {
    "cache-control": "private, no-store, no-cache, must-revalidate, max-age=0",
    "pragma": "no-cache",
    "expires": "0",
    "x-robots-tag": "noindex, nofollow",
    "vary": "Cookie"
  };

  if (!await validAdminSession(request)) {
    return new Response(null, {
      status: 302,
      headers: { ...headers, location: "/admin-login.html" }
    });
  }

  const response = await context.next();
  const responseHeaders = new Headers(response.headers);
  for (const [name, value] of Object.entries(headers)) responseHeaders.set(name, value);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  });
}

export const config = { path: "/admin.html" };
