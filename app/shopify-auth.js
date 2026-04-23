const crypto = require("crypto");

function sanitizeShop(shop) {
  if (!shop || typeof shop !== "string") return null;
  const s = shop.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(s)) return null;
  return s;
}

function buildInstallUrl({ shop, apiKey, scopes, redirectUri, state }) {
  const params = new URLSearchParams({
    client_id: apiKey,
    scope: scopes,
    redirect_uri: redirectUri,
    state
  });
  return `https://${shop}/admin/oauth/authorize?${params.toString()}`;
}

function verifyHmac(query) {
  const secret = process.env.SHOPIFY_API_SECRET;
  if (!secret) throw new Error("Missing SHOPIFY_API_SECRET");

  const entries = Object.entries(query)
    .filter(([key, value]) => key !== "hmac" && value !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(",") : value}`);

  const message = entries.join("&");
  const digest = crypto
    .createHmac("sha256", secret)
    .update(message)
    .digest("hex");

  const provided = String(query.hmac || "");
  if (!provided) return false;

  try {
    return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(provided, "utf8"));
  } catch {
    return false;
  }
}

function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}

async function exchangeCodeForToken({ shop, code }) {
  const url = `https://${shop}/admin/oauth/access_token`;
  const body = JSON.stringify({
    client_id: process.env.SHOPIFY_API_KEY,
    client_secret: process.env.SHOPIFY_API_SECRET,
    code,
    expiring: 1
  });

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed: ${res.status} ${text}`);
  }

  const json = await res.json();
  return {
    access_token: json.access_token,
    refresh_token: json.refresh_token || null,
    expires_in: json.expires_in || null
  };
}

module.exports = {
  sanitizeShop,
  buildInstallUrl,
  verifyHmac,
  generateNonce,
  exchangeCodeForToken
};
