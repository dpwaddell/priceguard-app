require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");
const {
  sanitizeShop,
  buildInstallUrl,
  verifyHmac,
  generateNonce,
  exchangeCodeForToken
} = require("./shopify-auth");

const app = express();
const port = process.env.PORT || 3100;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function safeTimingEqual(a, b) {
  const aBuf = Buffer.from(String(a || ""), "utf8");
  const bBuf = Buffer.from(String(b || ""), "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function verifyShopifyWebhookHmac(req) {
  const secret = process.env.SHOPIFY_API_SECRET || "";
  if (!secret) return false;

  const header = req.get("X-Shopify-Hmac-Sha256") || "";
  const rawBody = req.body && Buffer.isBuffer(req.body) ? req.body : Buffer.from("");

  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("base64");

  return safeTimingEqual(digest, header);
}

function parseWebhookJsonBody(req) {
  try {
    if (!req.body || !Buffer.isBuffer(req.body)) return {};
    const str = req.body.toString("utf8") || "{}";
    return JSON.parse(str);
  } catch {
    return {};
  }
}

app.use("/assets", express.static(path.join(__dirname, "public")));

async function shopifyAdminGraphQL(shopDomain, accessToken, query, variables = {}) {
  const apiVersion = "2026-04";
  const response = await fetch(`https://${shopDomain}/admin/api/${apiVersion}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken
    },
    body: JSON.stringify({ query, variables })
  });

  const json = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error("Shopify customer search request failed. Please try again.");
  }

  if (json.errors && json.errors.length) {
    const raw = JSON.stringify(json.errors);
    if (raw.includes("ACCESS_DENIED") || raw.includes("protected-customer-data") || raw.includes("Customer object")) {
      throw new Error("Customer search is unavailable until this app is approved for Shopify protected customer data. You can still create assignments manually for now.");
    }
    throw new Error("Shopify customer search failed. Please try again.");
  }

  return json.data || {};
}

async function searchShopifyCustomers(shopDomain, term) {
  const shopRes = await pool.query(
    `SELECT id, shop_domain, access_token
     FROM shops
     WHERE shop_domain = $1
     LIMIT 1`,
    [shopDomain]
  );

  if (shopRes.rowCount === 0) {
    throw new Error("Shop not found.");
  }

  const shop = shopRes.rows[0];

  if (!shop.access_token) {
    throw new Error("Shop does not have an access token.");
  }

  const cleaned = String(term || "").trim();
  if (!cleaned) return [];

  const query = `
    query CustomerLookup($query: String!) {
      customers(first: 12, query: $query) {
        edges {
          node {
            id
            displayName
            firstName
            lastName
            email
            phone
            tags
          }
        }
      }
    }
  `;

  const searchTerms = [
    cleaned,
    `email:${cleaned}`,
    `name:${cleaned}`
  ];

  const seen = new Map();

  for (const q of searchTerms) {
    const data = await shopifyAdminGraphQL(shop.shop_domain, shop.access_token, query, { query: q });
    const edges = (((data || {}).customers || {}).edges || []);
    for (const edge of edges) {
      const node = edge && edge.node ? edge.node : null;
      if (!node || !node.id) continue;

      const shortId = String(node.id).split("/").pop();
      seen.set(node.id, {
        id: node.id,
        short_id: shortId,
        display_name:
          node.displayName ||
          [node.firstName, node.lastName].filter(Boolean).join(" ").trim() ||
          node.email ||
          "Unnamed customer",
        email: node.email || "",
        phone: node.phone || "",
        tags: Array.isArray(node.tags) ? node.tags : []
      });
    }
  }

  return Array.from(seen.values());
}


function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function fmtDisplayDate(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("en-GB");
}

function ruleStatus(startsAt, endsAt, isEnabled) {
  if (!isEnabled) return "draft";
  const now = new Date();
  const start = startsAt ? new Date(startsAt) : null;
  const end = endsAt ? new Date(endsAt) : null;
  if (start && start > now) return "scheduled";
  if (end && end <= now) return "expired";
  return "live";
}

function badgeClass(status) {
  if (status === "live") return "live";
  if (status === "scheduled") return "scheduled";
  if (status === "expired") return "expired";
  return "draft";
}

function getEmbeddedAppUrl(shop, host = "", path = "/") {
  const base = process.env.APP_URL || "";
  const params = new URLSearchParams({ shop });
  if (host) params.set("host", host);
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return `${base}${cleanPath}?${params.toString()}`;
}

async function ensureShopAndSettings({ shopDomain, accessToken = null }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const shopRes = await client.query(
      `INSERT INTO shops (shop_domain, access_token, installed_at, plan_name, plan_status, created_at, updated_at)
       VALUES ($1, $2, NOW(), 'free', 'active', NOW(), NOW())
       ON CONFLICT (shop_domain)
       DO UPDATE SET
         access_token = COALESCE(EXCLUDED.access_token, shops.access_token),
         installed_at = COALESCE(shops.installed_at, NOW()),
         updated_at = NOW()
       RETURNING id, shop_domain, plan_name, plan_status`,
      [shopDomain, accessToken]
    );

    const shop = shopRes.rows[0];

    await client.query(
      `INSERT INTO settings (shop_id, onboarding_complete, created_at, updated_at)
       VALUES ($1, false, NOW(), NOW())
       ON CONFLICT (shop_id)
       DO NOTHING`,
      [shop.id]
    );

    await client.query(
      `INSERT INTO audit_logs (shop_id, actor_type, actor_email, action, entity_type, entity_id, metadata_json)
       VALUES ($1, 'system', 'system@priceguard.local', $2, 'shop', $3, $4::jsonb)`,
      [shop.id, accessToken ? "oauth_install_complete" : "shop_record_created", String(shop.id), JSON.stringify({ shop_domain: shopDomain })]
    );

    await client.query("COMMIT");
    return shop;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

async function getShopByDomain(shopDomain) {
  const res = await pool.query(
    `SELECT id, shop_domain, plan_name, plan_status, installed_at
     FROM shops
     WHERE shop_domain = $1
     LIMIT 1`,
    [shopDomain]
  );
  return res.rows[0] || null;
}

async function getDashboardData(shopDomain) {
  const client = await pool.connect();
  try {
    const shopRes = await client.query(
      `SELECT id, shop_domain, plan_name, plan_status, installed_at
       FROM shops
       WHERE shop_domain = $1
       LIMIT 1`,
      [shopDomain]
    );

    if (shopRes.rowCount === 0) return null;

    const shop = shopRes.rows[0];

    const settingsRes = await client.query(
      `SELECT onboarding_complete, free_plan_customer_limit, pricing_display_mode, app_enabled
       FROM settings
       WHERE shop_id = $1
       LIMIT 1`,
      [shop.id]
    );

    const tierCountRes = await client.query(
      `SELECT COUNT(*)::int AS count FROM pricing_tiers WHERE shop_id = $1`,
      [shop.id]
    );

    const assignmentCountRes = await client.query(
      `SELECT COUNT(*)::int AS count FROM customer_assignments WHERE shop_id = $1`,
      [shop.id]
    );

    const overrideCountRes = await client.query(
      `SELECT COUNT(*)::int AS count FROM customer_product_prices WHERE shop_id = $1`,
      [shop.id]
    );

    const importCountRes = await client.query(
      `SELECT COUNT(*)::int AS count FROM imports WHERE shop_id = $1`,
      [shop.id]
    );

    const settings = settingsRes.rows[0] || {
      onboarding_complete: false,
      free_plan_customer_limit: 1,
      pricing_display_mode: "replace",
      app_enabled: true
    };

    return {
      shop,
      settings,
      counts: {
        tiers: tierCountRes.rows[0].count,
        assignments: assignmentCountRes.rows[0].count,
        overrides: overrideCountRes.rows[0].count,
        imports: importCountRes.rows[0].count
      }
    };
  } finally {
    client.release();
  }
}

async function getPricingTiers(shopId) {
  const res = await pool.query(
    `SELECT id, name, customer_tag, discount_type, discount_value, is_enabled, starts_at, ends_at, created_at, updated_at
     FROM pricing_tiers
     WHERE shop_id = $1
     ORDER BY created_at DESC, id DESC`,
    [shopId]
  );
  return res.rows;
}

async function getCustomerAssignments(shopId) {
  const res = await pool.query(
    `SELECT
       ca.id,
       ca.shopify_customer_id,
       ca.customer_email,
       ca.tier_id,
       ca.starts_at,
       ca.ends_at,
       ca.is_enabled,
       ca.created_at,
       pt.name AS tier_name,
       pt.customer_tag AS tier_customer_tag
     FROM customer_assignments ca
     JOIN pricing_tiers pt ON pt.id = ca.tier_id
     WHERE ca.shop_id = $1
     ORDER BY ca.created_at DESC, ca.id DESC`,
    [shopId]
  );
  return res.rows;
}

async function getPricingPreview(shopId, customerEmail) {
  const res = await pool.query(
    `SELECT
       ca.id AS assignment_id,
       ca.customer_email,
       ca.shopify_customer_id,
       ca.starts_at AS assignment_starts_at,
       ca.ends_at AS assignment_ends_at,
       ca.is_enabled AS assignment_enabled,
       pt.id AS tier_id,
       pt.name AS tier_name,
       pt.customer_tag,
       pt.discount_type,
       pt.discount_value,
       pt.starts_at AS tier_starts_at,
       pt.ends_at AS tier_ends_at,
       pt.is_enabled AS tier_enabled
     FROM customer_assignments ca
     JOIN pricing_tiers pt
       ON pt.id = ca.tier_id
     WHERE ca.shop_id = $1
       AND LOWER(ca.customer_email) = LOWER($2)
     ORDER BY ca.created_at DESC, ca.id DESC
     LIMIT 1`,
    [shopId, customerEmail]
  );

  return res.rows[0] || null;
}

async function writeAudit(shopId, action, entityType, entityId, metadata = {}) {
  await pool.query(
    `INSERT INTO audit_logs (shop_id, actor_type, actor_email, action, entity_type, entity_id, metadata_json)
     VALUES ($1, 'system', 'system@priceguard.local', $2, $3, $4, $5::jsonb)`,
    [shopId, action, entityType, String(entityId), JSON.stringify(metadata)]
  );
}

function renderLayout({ shop, host, apiKey, title, content }) {
  const apiKeySafe = escapeHtml(apiKey || "");

  return `
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>${escapeHtml(title)}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
    <style>
      :root {
        --bg: #f6f6f7; --card: #fff; --text: #111827; --muted: #6b7280; --line: #e5e7eb;
        --soft: #f3f4f6; --success-bg: #ecfdf5; --success-text: #065f46;
        --todo-bg: #eff6ff; --todo-text: #1d4ed8; --danger-bg: #fef2f2; --danger-text: #991b1b;
        --warn-bg: #fff7ed; --warn-text: #9a3412;
      }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--text); }
      .wrap { max-width: 1180px; margin: 0 auto; padding: 24px; }
      .topbar { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; margin-bottom:20px; }
      .topbar h1 { margin:0 0 8px 0; font-size:32px; }
      .sub { color:var(--muted); max-width:760px; line-height:1.5; }
      .shop-meta { display:flex; gap:8px; flex-wrap:wrap; }
      .pill { display:inline-block; padding:6px 10px; border-radius:999px; background:var(--soft); font-size:12px; }
      .nav { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:18px; }
      .nav a {
        text-decoration:none; color:#111827; background:#fff; border:1px solid var(--line);
        padding:10px 14px; border-radius:12px; font-weight:600;
      }
      .nav a.active { background:#111827; color:#fff; border-color:#111827; }
      .grid { display:grid; grid-template-columns:1.45fr 1fr; gap:16px; }
      .stack { display:grid; gap:16px; }
      .card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:20px; }
      .card h2 { margin:0 0 12px 0; font-size:20px; }
      .muted { color:var(--muted); }
      .success { color:var(--success-text); }
      .mini-grid { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:12px; margin-top:16px; }
      .stat { background:var(--soft); border-radius:14px; padding:14px; }
      .stat-label { color:var(--muted); font-size:13px; margin-bottom:6px; }
      .stat-value { font-size:24px; font-weight:700; }
      .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:16px; }
      .btn, button.btn {
        appearance:none; border:1px solid var(--line); background:#fff; color:#111827;
        padding:10px 14px; border-radius:12px; cursor:pointer; font-weight:600; text-decoration:none;
      }
      .btn.primary, button.btn.primary { background:#111827; color:#fff; border-color:#111827; }
      .btn.danger, button.btn.danger { background:#fff; color:var(--danger-text); border-color:#fecaca; }
      .btn.small, button.btn.small { padding:8px 10px; font-size:13px; border-radius:10px; }
      .check-row { display:grid; grid-template-columns:28px 1fr; gap:12px; padding:12px 0; border-top:1px solid var(--line); }
      .check-row:first-of-type { border-top:0; }
      .check-badge {
        width:28px; height:28px; border-radius:999px; display:flex; align-items:center; justify-content:center; font-weight:700;
      }
      .check-badge.done { background:var(--success-bg); color:var(--success-text); }
      .check-badge.todo { background:var(--todo-bg); color:var(--todo-text); }
      .check-title { font-weight:700; margin-bottom:4px; }
      .check-desc { color:var(--muted); line-height:1.4; }
      .list { display:grid; gap:10px; }
      .list-row { display:flex; justify-content:space-between; gap:16px; padding:12px 0; border-top:1px solid var(--line); }
      .list-row:first-child { border-top:0; }
      .form-grid { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:14px; }
      .field { display:grid; gap:6px; }
      .field label { font-size:13px; font-weight:700; color:#374151; }
      .field input, .field select {
        width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:12px; background:#fff; color:#111827;
      }
      .field.full { grid-column:1 / -1; }
      table { width:100%; border-collapse:collapse; }
      th, td { text-align:left; padding:12px 10px; border-top:1px solid var(--line); vertical-align:top; }
      th { color:#6b7280; font-size:12px; text-transform:uppercase; letter-spacing:0.03em; }
      tr:first-child td, tr:first-child th { border-top:0; }
      .table-actions { display:flex; gap:8px; flex-wrap:wrap; }
      .inline-form { display:inline; }
      .badge {
        display:inline-block; padding:5px 9px; border-radius:999px; font-size:12px; font-weight:700;
      }
      .badge.live { background:var(--success-bg); color:var(--success-text); }
      .badge.scheduled { background:var(--todo-bg); color:var(--todo-text); }
      .badge.expired { background:var(--warn-bg); color:var(--warn-text); }
      .badge.draft { background:var(--soft); color:#374151; }
      .empty {
        border:1px dashed var(--line); border-radius:14px; padding:20px; background:#fafafa; color:var(--muted);
      }
      @media (max-width: 980px) {
        .grid { grid-template-columns:1fr; }
        .mini-grid { grid-template-columns:repeat(2, minmax(0, 1fr)); }
        .form-grid { grid-template-columns:1fr; }
      }
    
      .page-shell {
        max-width: 1180px;
        margin: 24px auto 40px;
        padding: 0 16px;
      }

      .brand-hero {
        background: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 24px;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.06);
        padding: 18px 22px;
        margin-bottom: 18px;
      }

      .brand-hero-top {
        display: flex;
        justify-content: space-between;
        gap: 18px;
        align-items: center;
        flex-wrap: wrap;
      }

      .brand-hero-left {
        display: flex;
        align-items: center;
        gap: 16px;
        min-width: 0;
      }

      .brand-logo-wrap {
        width: 60px;
        height: 60px;
        border-radius: 18px;
        background: #f8fafc;
        border: 1px solid #e5e7eb;
        display: flex;
        align-items: center;
        justify-content: center;
        flex: 0 0 auto;
        overflow: hidden;
      }

      .brand-logo-wrap img {
        width: 42px;
        height: 42px;
        object-fit: contain;
        display: block;
      }

      .brand-logo-fallback {
        width: 42px;
        height: 42px;
        border-radius: 14px;
        background: linear-gradient(135deg, #9acb4d 0%, #6fa53a 100%);
        color: #0b1f55;
        font-weight: 800;
        font-size: 18px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .brand-copy h1 {
        margin: 0;
        font-size: 28px;
        line-height: 1.1;
        color: #111827;
      }

      .brand-copy .sub {
        margin-top: 6px;
        color: #667085;
        font-size: 14px;
        line-height: 1.5;
        max-width: 720px;
      }

      .brand-meta {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        align-items: center;
      }

      .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        border-radius: 999px;
        padding: 8px 12px;
        font-size: 12px;
        font-weight: 700;
        border: 1px solid #dbe7d1;
        background: #f3faee;
        color: #2f6f2f;
      }

      .status-pill::before {
        content: "";
        width: 8px;
        height: 8px;
        border-radius: 999px;
        background: #72b043;
      }

      .brand-meta .pill {
        border-radius: 999px;
        padding: 8px 12px;
        font-size: 12px;
        font-weight: 600;
        border: 1px solid #e5e7eb;
        background: #ffffff;
        color: #344054;
      }

      .brand-nav {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 16px;
      }

      .brand-nav .btn {
        border-radius: 14px;
        font-weight: 700;
        padding: 10px 16px;
      }

      .card {
        border: 1px solid #e5e7eb !important;
        border-radius: 22px !important;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.04);
      }

      .btn.primary {
        background: #0b1f55 !important;
        border-color: #0b1f55 !important;
        color: #ffffff !important;
      }

      .btn {
        border-radius: 14px !important;
      }

      .badge.live {
        background: #eaf7e4 !important;
        color: #2f6f2f !important;
      }

      .empty {
        border-radius: 18px;
        border: 1px dashed #d8dee8;
        background: #fafbfc;
      }

      @media (max-width: 900px) {
        .brand-hero-top {
          align-items: flex-start;
        }

        .brand-copy h1 {
          font-size: 24px;
        }
      }

    
      /* --- PriceGuard premium UI override --- */
      body {
        background: #f4f6f8 !important;
      }

      .page-shell {
        max-width: 1180px !important;
        margin: 20px auto 40px !important;
        padding: 0 16px !important;
      }

      .brand-hero {
        border-radius: 28px !important;
        padding: 20px 22px 18px !important;
        margin-bottom: 20px !important;
        box-shadow: 0 12px 32px rgba(15, 23, 42, 0.06) !important;
      }

      .brand-hero-top {
        gap: 18px !important;
        align-items: center !important;
      }

      .brand-logo-wrap {
        width: 62px !important;
        height: 62px !important;
        border-radius: 18px !important;
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.7) !important;
      }

      .brand-logo-wrap img {
        width: 42px !important;
        height: 42px !important;
        object-fit: contain !important;
      }

      .brand-copy h1 {
        font-size: 28px !important;
        line-height: 1.05 !important;
        letter-spacing: -0.03em !important;
        color: #0f172a !important;
      }

      .brand-copy .sub {
        margin-top: 7px !important;
        font-size: 14px !important;
        line-height: 1.5 !important;
        max-width: 760px !important;
        color: #667085 !important;
      }

      .brand-meta,
      .brand-nav,
      .nav,
      .actions,
      .table-actions {
        gap: 10px !important;
      }

      .brand-nav,
      .nav {
        margin-top: 16px !important;
      }

      .status-pill,
      .brand-meta .pill {
        padding: 8px 14px !important;
        font-size: 12px !important;
        font-weight: 700 !important;
      }

      .grid {
        gap: 18px !important;
      }

      .stack {
        gap: 18px !important;
      }

      .card {
        border-radius: 26px !important;
        padding: 18px !important;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.04) !important;
      }

      .card h2 {
        margin: 0 0 14px 0 !important;
        font-size: 18px !important;
        line-height: 1.2 !important;
        letter-spacing: -0.02em !important;
        color: #111827 !important;
      }

      .muted,
      .sub {
        color: #667085 !important;
        line-height: 1.45 !important;
      }

      .btn {
        padding: 11px 16px !important;
        border-radius: 16px !important;
        font-weight: 700 !important;
        font-size: 14px !important;
        transition: all 0.15s ease !important;
        box-shadow: 0 1px 0 rgba(255,255,255,0.7) inset !important;
      }

      .btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 14px rgba(15, 23, 42, 0.06) !important;
      }

      .btn.primary {
        box-shadow: 0 8px 18px rgba(11, 31, 85, 0.18) !important;
      }

      .btn.primary:hover {
        box-shadow: 0 10px 20px rgba(11, 31, 85, 0.22) !important;
      }

      .btn.small {
        padding: 8px 12px !important;
        border-radius: 12px !important;
        font-size: 13px !important;
      }

      .stat,
      .stats .card,
      .stats > div {
        border-radius: 18px !important;
      }

      .stats {
        gap: 12px !important;
        margin-top: 14px !important;
      }

      table {
        border-collapse: collapse !important;
      }

      th {
        font-size: 12px !important;
        font-weight: 800 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.02em !important;
        color: #6b7280 !important;
        padding: 10px 10px 12px 0 !important;
      }

      td {
        padding: 12px 10px 12px 0 !important;
        border-top: 1px solid #edf0f3 !important;
        color: #111827 !important;
      }

      .badge {
        padding: 6px 10px !important;
        border-radius: 999px !important;
        font-size: 12px !important;
        font-weight: 800 !important;
      }

      .empty {
        border-radius: 20px !important;
        border: 1px dashed #d8dee8 !important;
        background: #fafbfc !important;
        padding: 18px !important;
        color: #667085 !important;
      }

      .list-row {
        padding: 14px 0 !important;
        border-top: 1px solid #edf0f3 !important;
      }

      input,
      select {
        border-radius: 14px !important;
        padding: 12px 14px !important;
        font-size: 14px !important;
      }

      input:focus,
      select:focus {
        box-shadow: 0 0 0 4px rgba(15, 23, 42, 0.04) !important;
      }

      @media (max-width: 980px) {
        .grid {
          grid-template-columns: 1fr !important;
        }
      }
      /* --- end premium UI override --- */

    
/* final submission polish safe */
.brand-hero{
  padding:16px 22px 14px !important;
}

.brand-nav,.nav{
  margin-top:12px !important;
}

.card{
  padding:16px !important;
}

.card h2{
  margin-bottom:12px !important;
}

.stats{
  margin-top:12px !important;
  gap:10px !important;
}

.stat{
  padding:12px !important;
}

.stat-label{
  font-size:12px !important;
  color:#6b7280 !important;
}

.stat-value{
  font-size:18px !important;
  font-weight:800 !important;
}

.check-row{
  padding:12px 0 !important;
}

.check-icon.todo{
  opacity:.75;
}

.list-row{
  padding:12px 0 !important;
}

.empty{
  min-height:auto !important;
}

</style>
  </head>
  <body>
    <div class="page-shell">
    <div class="wrap">
      ${content}
    </div>

    <script>
      const host = new URLSearchParams(window.location.search).get("host");
      if (host && window.shopify && window.shopify.createApp) {
        window.shopify.createApp({
          apiKey: "${apiKeySafe}",
          host,
          forceRedirect: true
        });
      }
    </script>
      </div>
  </body>
</html>
  `;
}

function renderPublicHome() {
  return `
    <html>
      <head>
        <title>PriceGuard</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 32px; color: #111; }
          .card { max-width: 760px; border: 1px solid #e5e7eb; border-radius: 12px; padding: 24px; }
          h1 { margin-top: 0; }
          ul { line-height: 1.7; }
          input { padding: 10px; width: 320px; }
          button { padding: 10px 14px; cursor: pointer; }
          .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>PriceGuard</h1>
          <p>Embedded App shell is ready.</p>
          <form class="row" method="get" action="/install">
            <input name="shop" placeholder="store-name.myshopify.com" />
            <button type="submit">Install App</button>
          </form>
          <ul>
            <li><a href="/health">/health</a></li>
            <li><a href="/debug/schema">/debug/schema</a></li>
            <li><a href="/debug/shops">/debug/shops</a></li>
          </ul>
        </div>
      </body>
    </html>
  `;
}


function renderBrandHero(opts) {
  const shop = opts.shop || "";
  const host = opts.host || "";
  const planName = opts.planName || "free";
  const statusText = opts.statusText || "active";
  const title = opts.title || "PriceGuard";
  const subtitle = opts.subtitle || "";
  const active = opts.active || "dashboard";

  const logoHtml =
    '<img src="/assets/priceguard-logo.png?v=4" alt="PriceGuard logo" onerror="this.style.display=\'none\'; this.nextElementSibling.style.display=\'flex\';" />' +
    '<div class="brand-logo-fallback" style="display:none;">PG</div>';

  return ''
    + '<div class="brand-hero">'
    +   '<div class="brand-hero-top">'
    +     '<div class="brand-hero-left">'
    +       '<div class="brand-logo-wrap">' + logoHtml + '</div>'
    +       '<div class="brand-copy">'
    +         '<h1>' + escapeHtml(title) + '</h1>'
    +         '<div class="sub">' + escapeHtml(subtitle) + '</div>'
    +       '</div>'
    +     '</div>'
    +     '<div class="brand-meta">'
    +       '<span class="status-pill">' + escapeHtml(statusText) + '</span>'
    +       '<span class="pill">Shop: ' + escapeHtml(shop) + '</span>'
    +       '<span class="pill">Plan: ' + escapeHtml(planName) + '</span>'
    +     '</div>'
    +   '</div>'
    +   '<div class="brand-nav">' + renderNav(shop, host, active) + '</div>'
    + '</div>';
}

function renderNav(shop, host, active) {
  const dashUrl = getEmbeddedAppUrl(shop, host, "/");
  const tiersUrl = getEmbeddedAppUrl(shop, host, "/pricing-tiers");
  const assignmentsUrl = getEmbeddedAppUrl(shop, host, "/customer-assignments");
  const previewUrl = getEmbeddedAppUrl(shop, host, "/pricing-preview");
  return `
    <div class="nav">
      <button type="button" class="btn ${active === "dashboard" ? "primary" : ""}" onclick="window.location.href='${dashUrl}'">Dashboard</button>
      <button type="button" class="btn ${active === "tiers" ? "primary" : ""}" onclick="window.location.href='${tiersUrl}'">Pricing Tiers</button>
      <button type="button" class="btn ${active === "assignments" ? "primary" : ""}" onclick="window.location.href='${assignmentsUrl}'">Customer Assignments</button>
      <button type="button" class="btn ${active === "preview" ? "primary" : ""}" onclick="window.location.href='${previewUrl}'">Pricing Preview</button>
    </div>
  `;
}

function renderDashboard({ shop, apiKey, dashboard, host }) {
  const shopSafe = escapeHtml(shop);
  const planName = escapeHtml(dashboard.shop.plan_name || "free");
  const planStatus = escapeHtml(dashboard.shop.plan_status || "inactive");
  const installedAt = dashboard.shop.installed_at
    ? new Date(dashboard.shop.installed_at).toLocaleString("en-GB")
    : "—";

  const customerLimit = Number(dashboard.settings.free_plan_customer_limit || 1);
  const assignedCount = Number(dashboard.counts.assignments || 0);
  const usageText = `${assignedCount} / ${customerLimit}`;
  const onboardingDone = !!dashboard.settings.onboarding_complete;
  const tierUrl = getEmbeddedAppUrl(shop, host, "/pricing-tiers");
  const assignmentsUrl = getEmbeddedAppUrl(shop, host, "/customer-assignments");

  const checklist = [
    { label: "Install App", done: true, desc: "OAuth and token storage complete." },
    { label: "Create First Pricing Tier", done: dashboard.counts.tiers > 0, desc: "Set up Gold, Silver, VIP or another trade tier." },
    { label: "Assign First Trade Customer", done: dashboard.counts.assignments > 0, desc: "Link a customer to a pricing tier." },
    { label: "Add Specific Product Prices", done: dashboard.counts.overrides > 0, desc: "Create customer-specific price overrides where needed." },
    { label: "Review Configuration", done: dashboard.counts.tiers > 0 && dashboard.counts.assignments > 0, desc: "Confirm your tier and customer assignment setup is ready for testing." }
  ];

  const checklistHtml = checklist.map(item => `
    <div class="check-row">
      <div class="check-badge ${item.done ? "done" : "todo"}">${item.done ? "✓" : "•"}</div>
      <div>
        <div class="check-title">${escapeHtml(item.label)}</div>
        <div class="check-desc">${escapeHtml(item.desc)}</div>
      </div>
    </div>
  `).join("");

  const content = `
    ${renderBrandHero({
      shop,
      host,
      planName: dashboard.shop.plan_name || "free",
      statusText: "Active",
      title: "PriceGuard",
      subtitle: "Customer pricing control for Trade, Wholesale and VIP accounts.",
      active: "dashboard"
    })}

    <div class="grid">
      <div class="stack">
        <div class="card">
          <h2>Get Started</h2>
          <div class="muted">
            PriceGuard is ready to configure. Create a pricing tier, assign a customer to that tier, and then test the setup with a customer account in your Shopify store.
          </div>

          <div class="actions">
            <a class="btn primary" href="${tierUrl}">Create First Pricing Tier</a>
            <a class="btn" href="${assignmentsUrl}">Assign Customer</a>
          </div>

          <div class="mini-grid">
            <div class="stat"><div class="stat-label">Trade Customers</div><div class="stat-value">${escapeHtml(usageText)}</div></div>
            <div class="stat"><div class="stat-label">Pricing Tiers</div><div class="stat-value">${dashboard.counts.tiers}</div></div>
            <div class="stat"><div class="stat-label">Price Overrides</div><div class="stat-value">${dashboard.counts.overrides}</div></div>
            <div class="stat"><div class="stat-label">CSV Imports</div><div class="stat-value">${dashboard.counts.imports}</div></div>
          </div>
        </div>

        <div class="card">
          <h2>Onboarding checklist</h2>
          ${checklistHtml}
        </div>
      </div>

      <div class="stack">
        <div class="card">
          <h2>Current Setup</h2>
          <div class="list">
            <div class="list-row"><div class="muted">Embedded App</div><div class="success">${host ? "Ready" : "Direct preview mode"}</div></div>
            <div class="list-row"><div class="muted">Install Status</div><div>${dashboard.shop.installed_at ? "Installed" : "Not installed"}</div></div>
            <div class="list-row"><div class="muted">Installed At</div><div>${escapeHtml(installedAt)}</div></div>
            <div class="list-row"><div class="muted">Onboarding Complete</div><div>${onboardingDone ? "Yes" : "Not yet"}</div></div>
            <div class="list-row"><div class="muted">Pricing Display Mode</div><div>${escapeHtml(dashboard.settings.pricing_display_mode || "replace")}</div></div>
            <div class="list-row"><div class="muted">App Enabled</div><div>${dashboard.settings.app_enabled ? "Yes" : "No"}</div></div>
          </div>
        </div>

        <div class="card">
          <h2>How PriceGuard Works</h2>
          <div class="muted">
            Create pricing tiers, assign customers, and validate pricing before launch.
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceGuard", content });
}

function renderPricingTiersPage({ shop, host, apiKey, dashboard, tiers }) {
  const rows = tiers.length === 0
    ? `<div class="empty">No pricing tiers yet. Create your first tier below to begin.</div>`
    : `
      <div class="card">
        <h2>Existing pricing tiers</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Customer tag</th>
              <th>Discount</th>
              <th>Effective from</th>
              <th>Effective to</th>
              <th>Status</th>
              <th style="width:220px;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${tiers.map((tier) => {
              const status = ruleStatus(tier.starts_at, tier.ends_at, tier.is_enabled);
              const discount =
                tier.discount_type === "percentage"
                  ? `${Number(tier.discount_value)}% off`
                  : `£${Number(tier.discount_value).toFixed(2)} off`;
              return `
                <tr>
                  <td><strong>${escapeHtml(tier.name)}</strong></td>
                  <td>${escapeHtml(tier.customer_tag || "—")}</td>
                  <td>${escapeHtml(discount)}</td>
                  <td>${escapeHtml(fmtDisplayDate(tier.starts_at))}</td>
                  <td>${escapeHtml(fmtDisplayDate(tier.ends_at))}</td>
                  <td><span class="badge ${badgeClass(status)}">${escapeHtml(status)}</span></td>
                  <td>
                    <div class="table-actions">
                      <form class="inline-form" method="post" action="/pricing-tiers/${tier.id}/toggle?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ""}">
                        <button class="btn small" type="submit">${tier.is_enabled ? "Disable" : "Enable"}</button>
                      </form>
                      <form class="inline-form" method="post" action="/pricing-tiers/${tier.id}/delete?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ""}" onsubmit="return confirm('Delete this pricing tier?');">
                        <button class="btn small danger" type="submit">Delete</button>
                      </form>
                    </div>
                  </td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;

  const content = `
    ${renderBrandHero({
      shop,
      host,
      planName: dashboard.shop.plan_name || "free",
      statusText: "Pricing Active",
      title: "Pricing Tiers",
      subtitle: "Create trade pricing rules with effective dates. Use tiers to manage wholesale, VIP and campaign pricing.",
      active: "tiers"
    })}

    <div class="grid">
      <div class="stack">
        ${rows}
      </div>

      <div class="stack">
        <div class="card">
          <h2>Create pricing tier</h2>
          <form method="post" action="/pricing-tiers?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ""}">
            <div class="form-grid">
              <div class="field">
                <label for="name">Tier name</label>
                <input id="name" name="name" placeholder="Gold" required />
              </div>

              <div class="field">
                <label for="customer_tag">Customer tag</label>
                <input id="customer_tag" name="customer_tag" placeholder="trade-gold" />
              </div>

              <div class="field">
                <label for="discount_type">Discount type</label>
                <select id="discount_type" name="discount_type" required>
                  <option value="percentage">Percentage</option>
                  <option value="fixed_amount">Fixed amount</option>
                </select>
              </div>

              <div class="field">
                <label for="discount_value">Discount value</label>
                <input id="discount_value" name="discount_value" type="number" step="0.01" min="0" placeholder="20" required />
              </div>

              <div class="field">
                <label for="starts_at">Effective from</label>
                <input id="starts_at" name="starts_at" type="datetime-local" />
              </div>

              <div class="field">
                <label for="ends_at">Effective to</label>
                <input id="ends_at" name="ends_at" type="datetime-local" />
              </div>

              <div class="field full">
                <label for="is_enabled">Status</label>
                <select id="is_enabled" name="is_enabled">
                  <option value="true">Enabled</option>
                  <option value="false">Draft / disabled</option>
                </select>
              </div>
            </div>

            <div class="actions">
              <button class="btn primary" type="submit">Create tier</button>
              <a class="btn" href="${getEmbeddedAppUrl(shop, host, "/")}">Back to dashboard</a>
            </div>
          </form>
        </div>

        <div class="card">
          <h2>How to use tiers</h2>
          <div class="list">
            <div class="list-row"><div>Gold</div><div class="muted">Top trade partners</div></div>
            <div class="list-row"><div>Silver</div><div class="muted">Standard wholesale</div></div>
            <div class="list-row"><div>VIP Event</div><div class="muted">Time-limited campaign</div></div>
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceGuard | Pricing Tiers", content });
}

function renderCustomerAssignmentsPage({ shop, host, apiKey, dashboard, tiers, assignments }) {
  const customerLimit = Number(dashboard.settings.free_plan_customer_limit || 1);

  const rows = assignments.length === 0
    ? `<div class="empty" style="min-height:140px; display:flex; align-items:flex-start;">No customer assignments yet. Create your first customer assignment to begin validating PriceGuard.</div>`
    : `
      <div class="card">
        <h2>Existing customer assignments</h2>
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Shopify customer ID</th>
              <th>Tier</th>
              <th>Effective from</th>
              <th>Effective to</th>
              <th>Status</th>
              <th style="width:220px;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${assignments.map((assignment) => {
              const status = ruleStatus(assignment.starts_at, assignment.ends_at, assignment.is_enabled);
              return `
                <tr>
                  <td><strong>${escapeHtml(assignment.customer_email)}</strong></td>
                  <td>${escapeHtml(assignment.shopify_customer_id || "—")}</td>
                  <td>
                    <div><strong>${escapeHtml(assignment.tier_name)}</strong></div>
                    <div class="muted">${escapeHtml(assignment.tier_customer_tag || "—")}</div>
                  </td>
                  <td>${escapeHtml(fmtDisplayDate(assignment.starts_at))}</td>
                  <td>${escapeHtml(fmtDisplayDate(assignment.ends_at))}</td>
                  <td><span class="badge ${badgeClass(status)}">${escapeHtml(status)}</span></td>
                  <td>
                    <div class="table-actions">
                      <form class="inline-form" method="post" action="/customer-assignments/${assignment.id}/toggle?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ""}">
                        <button class="btn small" type="submit">${assignment.is_enabled ? "Disable" : "Enable"}</button>
                      </form>
                      <form class="inline-form" method="post" action="/customer-assignments/${assignment.id}/delete?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ""}" onsubmit="return confirm('Delete this customer assignment?');">
                        <button class="btn small danger" type="submit">Delete</button>
                      </form>
                    </div>
                  </td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;

  const tierOptions = tiers.length === 0
    ? `<option value="">No tiers available</option>`
    : tiers.map((tier) => `<option value="${tier.id}">${escapeHtml(tier.name)}${tier.customer_tag ? ` (${escapeHtml(tier.customer_tag)})` : ""}</option>`).join("");

  const content = `
    ${renderBrandHero({
      shop,
      host,
      planName: dashboard.shop.plan_name || "free",
      statusText: "Manual Setup",
      title: "Customer Assignments",
      subtitle: "Link customers to pricing tiers and validate which accounts should receive special pricing.",
      active: "assignments"
    })}

    <div class="grid">
      <div class="stack">
        ${rows}
      </div>

      <div class="stack">
        <div class="card">
          <h2>Assign customer to tier</h2>
          <div class="actions" style="margin-bottom:12px;">
            <div class="empty" style="margin-bottom:12px;">Shopify customer search is not enabled in this version. Enter the customer email and optional Shopify customer ID manually below.</div>
          </div>
          <form method="post" action="/customer-assignments?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ""}">
            <div class="form-grid">
              <div class="field full">
                <label for="customer_email">Customer email</label>
                <input id="customer_email" name="customer_email" type="email" placeholder="buyer@example.com" required />
              </div>

              <div class="field full">
                <label for="shopify_customer_id">Shopify customer ID (optional)</label>
                <input id="shopify_customer_id" name="shopify_customer_id" placeholder="123456789" />
              </div>

              <div class="field full">
                <label for="tier_id">Pricing tier</label>
                <select id="tier_id" name="tier_id" required ${tiers.length === 0 ? "disabled" : ""}>
                  <option value="">Select a tier</option>
                  ${tierOptions}
                </select>
              </div>

              <div class="field">
                <label for="starts_at">Effective from</label>
                <input id="starts_at" name="starts_at" type="datetime-local" />
              </div>

              <div class="field">
                <label for="ends_at">Effective to</label>
                <input id="ends_at" name="ends_at" type="datetime-local" />
              </div>

              <div class="field full">
                <label for="is_enabled">Status</label>
                <select id="is_enabled" name="is_enabled">
                  <option value="true">Enabled</option>
                  <option value="false">Draft / disabled</option>
                </select>
              </div>
            </div>

            <div class="actions">
              <button class="btn primary" type="submit" ${tiers.length === 0 ? "disabled" : ""}>Create assignment</button>
              <a class="btn" href="${getEmbeddedAppUrl(shop, host, "/")}">Back to dashboard</a>
            </div>
          </form>
        </div>

        <div class="card">
          <h2>How assignments work</h2>
          <div class="list">
            <div class="list-row"><div>One row per customer</div><div class="muted">Clear and simple setup</div></div>
            <div class="list-row"><div>Email is primary</div><div class="muted">Easy to validate during testing</div></div>
            <div class="list-row"><div>Optional dates</div><div class="muted">Supports scheduled pricing windows</div></div>
            <div class="list-row"><div>Manual entry</div><div class="muted">Customer search can be added later</div></div>
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceGuard | Customer Assignments", content });
}

app.get("/", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const useEmail = String(req.query.use_email || "").trim();
    const useId = String(req.query.use_id || "").trim();

    if (shop) {
      const dashboard = await getDashboardData(shop);
      if (dashboard) {
        return res.send(renderDashboard({
          shop,
          apiKey: process.env.SHOPIFY_API_KEY || "",
          dashboard,
          host
        }));
      }
    }

    return res.send(renderPublicHome());
  } catch (e) {
    return res.status(500).send(`Root load failed: ${escapeHtml(e.message)}`);
  }
});

app.get("/pricing-tiers", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    if (!shop) return res.status(400).send("Missing or invalid shop.");

    const dashboard = await getDashboardData(shop);
    if (!dashboard) return res.status(404).send("Shop not found.");

    const tiers = await getPricingTiers(dashboard.shop.id);

    return res.send(renderPricingTiersPage({
      shop,
      host,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      dashboard,
      tiers
    }));
  } catch (e) {
    return res.status(500).send(`Pricing Tiers load failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/pricing-tiers", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    if (!shop) return res.status(400).send("Missing or invalid shop.");

    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send("Shop not found.");

    const name = String(req.body.name || "").trim();
    const customerTag = String(req.body.customer_tag || "").trim() || null;
    const discountType = String(req.body.discount_type || "").trim();
    const rawDiscountValue = String(req.body.discount_value || "").trim();
    const startsAt = String(req.body.starts_at || "").trim() || null;
    const endsAt = String(req.body.ends_at || "").trim() || null;
    const isEnabled = String(req.body.is_enabled || "true") === "true";

    if (!name) return res.status(400).send("Tier name is required.");
    if (!["percentage", "fixed_amount"].includes(discountType)) {
      return res.status(400).send("Invalid discount type.");
    }

    const discountValue = Number(rawDiscountValue);
    if (!Number.isFinite(discountValue) || discountValue < 0) {
      return res.status(400).send("Discount value must be a valid positive number.");
    }

    const insert = await pool.query(
      `INSERT INTO pricing_tiers
        (shop_id, name, customer_tag, discount_type, discount_value, is_enabled, starts_at, ends_at, created_at, updated_at)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, NOW(), NOW())
       RETURNING id`,
      [shopRow.id, name, customerTag, discountType, discountValue, isEnabled, startsAt, endsAt]
    );

    await writeAudit(shopRow.id, "pricing_tier_created", "pricing_tier", insert.rows[0].id, {
      name,
      customer_tag: customerTag,
      discount_type: discountType,
      discount_value: discountValue
    });

    return res.redirect(getEmbeddedAppUrl(shop, host, "/pricing-tiers"));
  } catch (e) {
    return res.status(500).send(`Create pricing tier failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/pricing-tiers/:id/toggle", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const id = Number(req.params.id);
    if (!shop || !Number.isFinite(id)) return res.status(400).send("Invalid request.");

    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send("Shop not found.");

    const current = await pool.query(
      `SELECT id, is_enabled, name
       FROM pricing_tiers
       WHERE id = $1 AND shop_id = $2
       LIMIT 1`,
      [id, shopRow.id]
    );

    if (current.rowCount === 0) return res.status(404).send("Tier not found.");

    const newValue = !current.rows[0].is_enabled;

    await pool.query(
      `UPDATE pricing_tiers
       SET is_enabled = $1, updated_at = NOW()
       WHERE id = $2 AND shop_id = $3`,
      [newValue, id, shopRow.id]
    );

    await writeAudit(shopRow.id, "pricing_tier_toggled", "pricing_tier", id, {
      name: current.rows[0].name,
      is_enabled: newValue
    });

    return res.redirect(getEmbeddedAppUrl(shop, host, "/pricing-tiers"));
  } catch (e) {
    return res.status(500).send(`Toggle pricing tier failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/pricing-tiers/:id/delete", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const id = Number(req.params.id);
    if (!shop || !Number.isFinite(id)) return res.status(400).send("Invalid request.");

    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send("Shop not found.");

    const current = await pool.query(
      `SELECT id, name
       FROM pricing_tiers
       WHERE id = $1 AND shop_id = $2
       LIMIT 1`,
      [id, shopRow.id]
    );

    if (current.rowCount === 0) return res.status(404).send("Tier not found.");

    await pool.query(
      `DELETE FROM pricing_tiers
       WHERE id = $1 AND shop_id = $2`,
      [id, shopRow.id]
    );

    await writeAudit(shopRow.id, "pricing_tier_deleted", "pricing_tier", id, {
      name: current.rows[0].name
    });

    return res.redirect(getEmbeddedAppUrl(shop, host, "/pricing-tiers"));
  } catch (e) {
    return res.status(500).send(`Delete pricing tier failed: ${escapeHtml(e.message)}`);
  }
});


app.get("/customer-assignments", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const lookup = String(req.query.lookup || "").trim();
    const useEmail = String(req.query.use_email || "").trim();
    const useId = String(req.query.use_id || "").trim();
    if (!shop) return res.status(400).send("Missing or invalid shop.");

    const dashboard = await getDashboardData(shop);
    if (!dashboard) return res.status(404).send("Shop not found.");

    const tiers = await getPricingTiers(dashboard.shop.id);
    const assignments = await getCustomerAssignments(dashboard.shop.id);

    return res.send(renderCustomerAssignmentsPage({
      shop,
      host,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      dashboard,
      tiers,
      assignments,
      prefillEmail: useEmail,
      prefillId: useId
    }));
  } catch (e) {
    return res.status(500).send(`Customer Assignments load failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/customer-assignments", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    if (!shop) return res.status(400).send("Missing or invalid shop.");

    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send("Shop not found.");

    const dashboard = await getDashboardData(shop);
    const limit = Number(dashboard?.settings?.free_plan_customer_limit || 1);

    const customerEmail = String(req.body.customer_email || "").trim().toLowerCase();
    const shopifyCustomerId = String(req.body.shopify_customer_id || "").trim() || null;
    const tierId = Number(req.body.tier_id);
    const startsAt = String(req.body.starts_at || "").trim() || null;
    const endsAt = String(req.body.ends_at || "").trim() || null;
    const isEnabled = String(req.body.is_enabled || "true") === "true";

    if (!customerEmail) return res.status(400).send("Customer email is required.");
    if (!Number.isFinite(tierId)) return res.status(400).send("Valid tier is required.");

    const tierCheck = await pool.query(
      `SELECT id, name
       FROM pricing_tiers
       WHERE id = $1 AND shop_id = $2
       LIMIT 1`,
      [tierId, shopRow.id]
    );
    if (tierCheck.rowCount === 0) return res.status(400).send("Tier not found for this shop.");

    const distinctCustomerCount = await pool.query(
      `SELECT COUNT(DISTINCT customer_email)::int AS count
       FROM customer_assignments
       WHERE shop_id = $1`,
      [shopRow.id]
    );

    const existingCustomer = await pool.query(
      `SELECT 1
       FROM customer_assignments
       WHERE shop_id = $1 AND customer_email = $2
       LIMIT 1`,
      [shopRow.id, customerEmail]
    );

    const currentDistinct = distinctCustomerCount.rows[0].count;
    const isNewCustomer = existingCustomer.rowCount === 0;

    if (isNewCustomer && currentDistinct >= limit) {
      return res.status(400).send(`Free plan limit reached. This shop can only have ${limit} trade customer(s).`);
    }

    const insert = await pool.query(
      `INSERT INTO customer_assignments
        (shop_id, shopify_customer_id, customer_email, tier_id, starts_at, ends_at, is_enabled, created_at, updated_at)
       VALUES
        ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, $7, NOW(), NOW())
       RETURNING id`,
      [shopRow.id, shopifyCustomerId, customerEmail, tierId, startsAt, endsAt, isEnabled]
    );

    await writeAudit(shopRow.id, "customer_assignment_created", "customer_assignment", insert.rows[0].id, {
      customer_email: customerEmail,
      shopify_customer_id: shopifyCustomerId,
      tier_id: tierId
    });

    return res.redirect(getEmbeddedAppUrl(shop, host, "/customer-assignments"));
  } catch (e) {
    return res.status(500).send(`Create customer assignment failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/customer-assignments/:id/toggle", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const id = Number(req.params.id);
    if (!shop || !Number.isFinite(id)) return res.status(400).send("Invalid request.");

    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send("Shop not found.");

    const current = await pool.query(
      `SELECT id, is_enabled, customer_email
       FROM customer_assignments
       WHERE id = $1 AND shop_id = $2
       LIMIT 1`,
      [id, shopRow.id]
    );
    if (current.rowCount === 0) return res.status(404).send("Assignment not found.");

    const newValue = !current.rows[0].is_enabled;

    await pool.query(
      `UPDATE customer_assignments
       SET is_enabled = $1, updated_at = NOW()
       WHERE id = $2 AND shop_id = $3`,
      [newValue, id, shopRow.id]
    );

    await writeAudit(shopRow.id, "customer_assignment_toggled", "customer_assignment", id, {
      customer_email: current.rows[0].customer_email,
      is_enabled: newValue
    });

    return res.redirect(getEmbeddedAppUrl(shop, host, "/customer-assignments"));
  } catch (e) {
    return res.status(500).send(`Toggle customer assignment failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/customer-assignments/:id/delete", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const id = Number(req.params.id);
    if (!shop || !Number.isFinite(id)) return res.status(400).send("Invalid request.");

    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send("Shop not found.");

    const current = await pool.query(
      `SELECT id, customer_email
       FROM customer_assignments
       WHERE id = $1 AND shop_id = $2
       LIMIT 1`,
      [id, shopRow.id]
    );
    if (current.rowCount === 0) return res.status(404).send("Assignment not found.");

    await pool.query(
      `DELETE FROM customer_assignments
       WHERE id = $1 AND shop_id = $2`,
      [id, shopRow.id]
    );

    await writeAudit(shopRow.id, "customer_assignment_deleted", "customer_assignment", id, {
      customer_email: current.rows[0].customer_email
    });

    return res.redirect(getEmbeddedAppUrl(shop, host, "/customer-assignments"));
  } catch (e) {
    return res.status(500).send(`Delete customer assignment failed: ${escapeHtml(e.message)}`);
  }
});


function renderPricingPreviewPage({ shop, host, apiKey, customerEmail = "", preview = null }) {
  const assignmentState = preview
    ? ruleStatus(preview.assignment_starts_at, preview.assignment_ends_at, preview.assignment_enabled)
    : "";
  const tierState = preview
    ? ruleStatus(preview.tier_starts_at, preview.tier_ends_at, preview.tier_enabled)
    : "";

  let resolvedStatus = "";
  if (preview) {
    if (!preview.assignment_enabled || !preview.tier_enabled) {
      resolvedStatus = "disabled";
    } else if (assignmentState === "live" && tierState === "live") {
      resolvedStatus = "active";
    } else {
      resolvedStatus = "scheduled_or_expired";
    }
  }

  const statusBadgeClass =
    resolvedStatus === "active" ? "live" :
    resolvedStatus === "disabled" ? "draft" :
    "scheduled";

  const effectiveDiscount = preview
    ? preview.discount_type === "percentage"
      ? `${Number(preview.discount_value)}% off`
      : `£${Number(preview.discount_value).toFixed(2)} off`
    : "—";

  const resultCard = !customerEmail
    ? `<div class="empty">Enter a customer email to preview the currently assigned pricing rule.</div>`
    : !preview
      ? `<div class="empty">No pricing assignment found for that customer email.</div>`
      : `
        <div class="card">
          <h2>Resolved pricing</h2>
          <div class="list">
            <div class="list-row"><div class="muted">Customer email</div><div>${escapeHtml(preview.customer_email || "—")}</div></div>
            <div class="list-row"><div class="muted">Shopify customer ID</div><div>${escapeHtml(preview.shopify_customer_id || "—")}</div></div>
            <div class="list-row"><div class="muted">Tier</div><div><strong>${escapeHtml(preview.tier_name || "—")}</strong></div></div>
            <div class="list-row"><div class="muted">Discount</div><div>${escapeHtml(effectiveDiscount)}</div></div>
            <div class="list-row"><div class="muted">Customer tag on tier</div><div>${escapeHtml(preview.customer_tag || "—")}</div></div>
            <div class="list-row"><div class="muted">Assignment window</div><div>${escapeHtml(fmtDisplayDate(preview.assignment_starts_at))} → ${escapeHtml(fmtDisplayDate(preview.assignment_ends_at))}</div></div>
            <div class="list-row"><div class="muted">Tier window</div><div>${escapeHtml(fmtDisplayDate(preview.tier_starts_at))} → ${escapeHtml(fmtDisplayDate(preview.tier_ends_at))}</div></div>
            <div class="list-row"><div class="muted">Current status</div><div><span class="badge ${statusBadgeClass}">${escapeHtml(resolvedStatus)}</span></div></div>
          </div>
        </div>
      `;

  const content = `
    ${renderBrandHero({
      shop,
      host,
      planName: "Preview",
      statusText: "Validation",
      title: "Pricing Preview",
      subtitle: "Preview the currently resolved pricing rule for a customer email before testing in store.",
      active: "preview"
    })}

    <div class="grid">
      <div class="stack">
        <div class="card">
          <h2>Lookup customer pricing</h2>
          <form method="get" action="/pricing-preview">
            <input type="hidden" name="shop" value="${escapeHtml(shop)}" />
            ${host ? `<input type="hidden" name="host" value="${escapeHtml(host)}" />` : ""}
            <div class="form-grid">
              <div class="field full">
                <label for="customer_email">Customer email</label>
                <input id="customer_email" name="customer_email" type="email" value="${escapeHtml(customerEmail)}" placeholder="buyer@example.com" required />
              </div>
            </div>
            <div class="actions">
              <button class="btn primary" type="submit">Preview pricing</button>
              <button type="button" class="btn" onclick="window.location.href='${getEmbeddedAppUrl(shop, host, "/customer-assignments")}';">Back to assignments</button>
            </div>
          </form>
        </div>

        ${resultCard}
      </div>

      <div class="stack">
        <div class="card">
          <h2>What this shows</h2>
          <div class="list">
            <div class="list-row"><div>Assigned tier</div><div class="muted">Latest matching assignment</div></div>
            <div class="list-row"><div>Discount</div><div class="muted">Type and value from tier</div></div>
            <div class="list-row"><div>Status</div><div class="muted">Based on enabled state and dates</div></div>
            <div class="list-row"><div>Validation</div><div class="muted">Useful before storefront testing</div></div>
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceGuard | Pricing Preview", content });
}


app.get("/pricing-preview", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const customerEmail = String(req.query.customer_email || "").trim();

    if (!shop) {
      return res.status(400).send("Missing or invalid shop.");
    }

    const dashboard = await getDashboardData(shop);
    if (!dashboard) {
      return res.status(404).send("Shop not found.");
    }

    let preview = null;
    if (customerEmail) {
      preview = await getPricingPreview(dashboard.shop.id, customerEmail);
    }

    return res.send(renderPricingPreviewPage({
      shop,
      host,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      customerEmail,
      preview
    }));
  } catch (e) {
    return res.status(500).send(`Pricing Preview load failed: ${escapeHtml(e.message)}`);
  }
});




app.post("/webhooks/customers/data_request", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!verifyShopifyWebhookHmac(req)) {
      return res.status(400).send("Invalid webhook signature");
    }

    const payload = parseWebhookJsonBody(req);
    console.log("[SHOPIFY_COMPLIANCE] customers/data_request", {
      shop: req.get("X-Shopify-Shop-Domain") || "",
      payload
    });

    return res.status(200).send("OK");
  } catch (err) {
    console.error("[SHOPIFY_COMPLIANCE] customers/data_request failed", err);
    return res.status(200).send("OK");
  }
});

app.post("/webhooks/customers/redact", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!verifyShopifyWebhookHmac(req)) {
      return res.status(400).send("Invalid webhook signature");
    }

    const payload = parseWebhookJsonBody(req);
    console.log("[SHOPIFY_COMPLIANCE] customers/redact", {
      shop: req.get("X-Shopify-Shop-Domain") || "",
      payload
    });

    return res.status(200).send("OK");
  } catch (err) {
    console.error("[SHOPIFY_COMPLIANCE] customers/redact failed", err);
    return res.status(200).send("OK");
  }
});

app.post("/webhooks/shop/redact", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!verifyShopifyWebhookHmac(req)) {
      return res.status(400).send("Invalid webhook signature");
    }

    const payload = parseWebhookJsonBody(req);
    console.log("[SHOPIFY_COMPLIANCE] shop/redact", {
      shop: req.get("X-Shopify-Shop-Domain") || "",
      payload
    });

    return res.status(200).send("OK");
  } catch (err) {
    console.error("[SHOPIFY_COMPLIANCE] shop/redact failed", err);
    return res.status(200).send("OK");
  }
});



app.post("/webhooks/compliance", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!verifyShopifyWebhookHmac(req)) {
      return res.status(400).send("Invalid webhook signature");
    }

    const payload = parseWebhookJsonBody(req);
    const topic = req.get("X-Shopify-Topic") || "";

    console.log("[SHOPIFY_COMPLIANCE] generic", {
      topic,
      shop: req.get("X-Shopify-Shop-Domain") || "",
      payload
    });

    return res.status(200).send("OK");
  } catch (err) {
    console.error("[SHOPIFY_COMPLIANCE] generic failed", err);
    return res.status(200).send("OK");
  }
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT NOW()");
    res.json({
      ok: true,
      app: process.env.APP_NAME,
      db: true,
      app_url: process.env.APP_URL || null,
      has_shopify_key: !!process.env.SHOPIFY_API_KEY,
      has_shopify_secret: !!process.env.SHOPIFY_API_SECRET
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/install", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    if (!shop) {
      return res.status(400).send("Invalid or missing shop parameter.");
    }

    const apiKey = process.env.SHOPIFY_API_KEY;
    const scopes = process.env.SHOPIFY_SCOPES;
    const appUrl = process.env.APP_URL;

    if (!apiKey || !scopes || !appUrl) {
      return res.status(500).send("Missing Shopify app configuration.");
    }

    const state = generateNonce();
    const redirectUri = `${appUrl}/auth/callback`;
    const installUrl = buildInstallUrl({
      shop,
      apiKey,
      scopes,
      redirectUri,
      state
    });

    return res.redirect(installUrl);
  } catch (e) {
    return res.status(500).send(`Install failed: ${escapeHtml(e.message)}`);
  }
});

app.get("/auth/callback", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const code = String(req.query.code || "");
    const host = String(req.query.host || "");

    if (!shop || !code) {
      return res.status(400).send("Missing shop or code.");
    }

    if (!verifyHmac(req.query)) {
      return res.status(400).send("Invalid HMAC.");
    }

    const tokenResponse = await exchangeCodeForToken({ shop, code });
    const accessToken = tokenResponse.access_token;

    if (!accessToken) {
      return res.status(500).send("No access token returned by Shopify.");
    }

    await ensureShopAndSettings({
      shopDomain: shop,
      accessToken
    });

    return res.redirect(getEmbeddedAppUrl(shop, host, "/"));
  } catch (e) {
    return res.status(500).send(`Auth callback failed: ${escapeHtml(e.message)}`);
  }
});

app.get("/app", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");

    if (!shop) {
      return res.status(400).send("Missing or invalid shop.");
    }

    const dashboard = await getDashboardData(shop);
    if (!dashboard) {
      return res.status(404).send("Shop not found. Reinstall the app from Shopify.");
    }

    return res.send(renderDashboard({
      shop,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      dashboard,
      host
    }));
  } catch (e) {
    return res.status(500).send(`Embedded App load failed: ${escapeHtml(e.message)}`);
  }
});

app.get("/debug/schema", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
      ORDER BY table_name ASC
    `);

    res.json({
      ok: true,
      tables: result.rows.map(r => r.table_name)
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/debug/shops", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, shop_domain, plan_name, plan_status, installed_at, created_at, updated_at,
             CASE WHEN access_token IS NULL THEN false ELSE true END AS has_access_token
      FROM shops
      ORDER BY id ASC
    `);

    res.json({
      ok: true,
      shops: result.rows
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});



app.get('/privacy', (req, res) => {
  res.send(`
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PriceGuard Privacy Policy</title>
<style>
body{
  margin:0;
  background:#f4f6f8;
  color:#111827;
  font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
.wrap{
  max-width:900px;
  margin:40px auto;
  padding:0 20px;
}
.card{
  background:#fff;
  border:1px solid #e5e7eb;
  border-radius:24px;
  padding:32px;
  box-shadow:0 10px 30px rgba(15,23,42,.06);
}
h1{
  margin:0 0 10px;
  font-size:34px;
}
h2{
  margin:28px 0 10px;
  font-size:22px;
}
p,li{
  color:#4b5563;
  line-height:1.65;
}
.small{
  color:#6b7280;
  font-size:14px;
}
a{
  color:#0b1f55;
  text-decoration:none;
}
</style>
</head>
<body>
<div class="wrap">
<div class="card">
<h1>Privacy Policy</h1>
<p class="small">Last updated: 2026-04-21</p>

<p>PriceGuard respects your privacy and is committed to protecting merchant data.</p>

<h2>Information We Collect</h2>
<ul>
<li>Store information required to install and operate the app</li>
<li>Configuration data such as pricing tiers and customer assignments</li>
<li>Limited technical logs used for security, support and troubleshooting</li>
</ul>

<h2>How We Use Information</h2>
<ul>
<li>Provide customer pricing functionality inside Shopify</li>
<li>Maintain app security and reliability</li>
<li>Respond to support requests</li>
<li>Improve the app experience</li>
</ul>

<h2>Data Sharing</h2>
<p>We do not sell merchant data. Data is only shared with service providers required to operate the app or where required by law.</p>

<h2>Data Retention</h2>
<p>We retain data only as long as necessary to provide the service and meet legal obligations.</p>

<h2>Security</h2>
<p>We use reasonable technical and organisational measures to protect data.</p>

<h2>Your Rights</h2>
<p>You may request access, correction or deletion of your data where applicable.</p>

<h2>Contact</h2>
<p>Email: <a href="mailto:contact@sample-guard.com">contact@sample-guard.com</a></p>

</div>
</div>
</body>
</html>
`);
});

app.listen(port, () => {
  console.log(`PriceGuard listening on ${port}`);
});
