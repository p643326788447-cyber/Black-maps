export default async function handler(request) {
  const headers = {
    "cache-control": "no-store, no-cache, must-revalidate",
    "pragma": "no-cache",
    "x-robots-tag": "noindex, nofollow"
  };

  try {
    const cookie = request.headers.get("cookie") || "";
    const checkUrl = new URL("/.netlify/functions/api?action=me", request.url);
    const check = await fetch(checkUrl, {
      method: "GET",
      headers: { cookie },
      cache: "no-store",
      redirect: "manual"
    });

    if (check.ok) return;
  } catch (error) {
    console.error("BLACK MAPS admin guard check failed:", error);
  }

  return new Response(null, {
    status: 302,
    headers: { ...headers, location: "/admin-login.html" }
  });
}

export const config = { path: "/admin.html" };
