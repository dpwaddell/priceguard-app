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

const APP_VERSION = require("./package.json").version;

const app = express();
const port = process.env.PORT || 3100;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const oauthStates = new Map();

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

async function createShopifySubscription(shopDomain, accessToken, returnUrl, planName = 'pro') {
  const PLAN_CONFIG = {
    growth: { name: 'PriceGuard Growth', price: 9.99 },
    pro:    { name: 'PriceGuard Pro',    price: 19.99 }
  };
  const plan = PLAN_CONFIG[planName] || PLAN_CONFIG.pro;

  const mutation = `#graphql
    mutation AppSubscriptionCreate(
      $name: String!
      $lineItems: [AppSubscriptionLineItemInput!]!
      $returnUrl: URL!
      $trialDays: Int!
    ) {
      appSubscriptionCreate(
        name: $name
        lineItems: $lineItems
        returnUrl: $returnUrl
        trialDays: $trialDays
      ) {
        appSubscription { id status }
        confirmationUrl
        userErrors { field message }
      }
    }
  `;

  const variables = {
    name: plan.name,
    returnUrl,
    trialDays: 14,
    lineItems: [
      {
        plan: {
          appRecurringPricingDetails: {
            price: { amount: plan.price, currencyCode: "USD" },
            interval: "EVERY_30_DAYS"
          }
        }
      }
    ]
  };

  const response = await fetch(`https://${shopDomain}/admin/api/2026-04/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken
    },
    body: JSON.stringify({ query: mutation, variables })
  });

  if (!response.ok) {
    throw new Error(`Shopify billing API returned ${response.status}`);
  }

  const json = await response.json();

  if (json.errors?.length) {
    throw new Error(`Billing mutation error: ${JSON.stringify(json.errors)}`);
  }

  const result = json.data?.appSubscriptionCreate;
  if (result?.userErrors?.length) {
    throw new Error(`Billing user error: ${result.userErrors.map(e => e.message).join(", ")}`);
  }

  return result?.confirmationUrl || null;
}

async function getActiveSubscription(shopDomain, accessToken) {
  const query = `#graphql
    query {
      currentAppInstallation {
        activeSubscriptions {
          id
          name
          status
          trialDays
          currentPeriodEnd
          lineItems {
            id
            plan {
              pricingDetails {
                ... on AppRecurringPricing {
                  price { amount currencyCode }
                  interval
                }
              }
            }
          }
        }
      }
    }
  `;

  const response = await fetch(`https://${shopDomain}/admin/api/2026-04/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken
    },
    body: JSON.stringify({ query })
  });

  if (!response.ok) {
    throw new Error(`Shopify billing query returned ${response.status}`);
  }

  const json = await response.json();

  if (json.errors?.length) {
    throw new Error(`Billing query error: ${JSON.stringify(json.errors)}`);
  }

  const subs = json.data?.currentAppInstallation?.activeSubscriptions || [];
  return subs.length > 0 ? subs[0] : null;
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

async function ensureShopAndSettings({ shopDomain, accessToken = null, refreshToken = null, expiresIn = null }) {
  const tokenExpiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const shopRes = await client.query(
      `INSERT INTO shops (shop_domain, access_token, refresh_token, token_expires_at, installed_at, plan_name, plan_status, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), 'free', 'active', NOW(), NOW())
       ON CONFLICT (shop_domain)
       DO UPDATE SET
         access_token = COALESCE(EXCLUDED.access_token, shops.access_token),
         refresh_token = COALESCE(EXCLUDED.refresh_token, shops.refresh_token),
         token_expires_at = COALESCE(EXCLUDED.token_expires_at, shops.token_expires_at),
         installed_at = COALESCE(shops.installed_at, NOW()),
         updated_at = NOW()
       RETURNING id, shop_domain, plan_name, plan_status`,
      [shopDomain, accessToken, refreshToken, tokenExpiresAt]
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
      `SELECT onboarding_complete, free_plan_customer_limit, pricing_display_mode, app_enabled, reviewed_at
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
      app_enabled: true,
      reviewed_at: null
    };

    if (!settings.onboarding_complete) {
      const allDone =
        tierCountRes.rows[0].count > 0 &&
        assignmentCountRes.rows[0].count > 0 &&
        (overrideCountRes.rows[0].count > 0 || !!settings.reviewed_at) &&
        !!settings.reviewed_at;
      if (allDone) {
        await client.query(
          `UPDATE settings SET onboarding_complete = true, updated_at = NOW() WHERE shop_id = $1`,
          [shop.id]
        );
        settings.onboarding_complete = true;
      }
    }

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

function getPlanLimits(planName) {
  switch (planName) {
    case 'growth': return { tierLimit: 3,    customerLimit: 20,   skuOverrides: true,  csvImport: false, scheduling: false };
    case 'pro':    return { tierLimit: null,  customerLimit: null, skuOverrides: true,  csvImport: true,  scheduling: true  };
    default:       return { tierLimit: 1,     customerLimit: 1,    skuOverrides: false, csvImport: false, scheduling: false };
  }
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
    <div style="margin-top:32px;padding:16px 0 8px;border-top:1px solid #e5e7eb;text-align:center;font-size:13px;color:#9ca3af;">
      PriceGuard v${APP_VERSION} &middot;
      <a href="/privacy" target="_blank" style="color:#9ca3af;text-decoration:none;">Privacy Policy</a> &middot;
      <a href="/terms" target="_blank" style="color:#9ca3af;text-decoration:none;">Terms of Service</a> &middot;
      <a href="mailto:support@sample-guard.com" style="color:#9ca3af;text-decoration:none;">Support</a>
    </div>
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
  const pricesUrl = getEmbeddedAppUrl(shop, host, "/customer-product-prices");
  return `
    <div class="nav" style="overflow-x:auto;flex-wrap:nowrap;white-space:nowrap;">
      <button type="button" class="btn ${active === "dashboard" ? "primary" : ""}" onclick="window.location.href='${dashUrl}'">Dashboard</button>
      <button type="button" class="btn ${active === "tiers" ? "primary" : ""}" onclick="window.location.href='${tiersUrl}'">Pricing Tiers</button>
      <button type="button" class="btn ${active === "assignments" ? "primary" : ""}" onclick="window.location.href='${assignmentsUrl}'">Customer Assignments</button>
      <button type="button" class="btn ${active === "prices" ? "primary" : ""}" onclick="window.location.href='${pricesUrl}'">Price Overrides</button>
      <button type="button" class="btn ${active === "preview" ? "primary" : ""}" onclick="window.location.href='${previewUrl}'">Pricing Preview</button>
      <a class="btn" href="${getEmbeddedAppUrl(shop, host, '/support')}" onclick="event.preventDefault(); window.open('https://priceguard.sample-guard.com/support','_blank')" style="text-decoration:none;">Support</a>
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

  const { customerLimit } = getPlanLimits(dashboard.shop.plan_name);
  const assignedCount = Number(dashboard.counts.assignments || 0);
  const usageText = customerLimit !== null ? `${assignedCount} / ${customerLimit}` : String(assignedCount);
  const onboardingDone = !!dashboard.settings.onboarding_complete;
  const tierUrl = getEmbeddedAppUrl(shop, host, "/pricing-tiers");
  const assignmentsUrl = getEmbeddedAppUrl(shop, host, "/customer-assignments");

  const checklist = [
    { label: "Install App", done: true, desc: "OAuth and token storage complete." },
    { label: "Create First Pricing Tier", done: dashboard.counts.tiers > 0, desc: "Set up Gold, Silver, VIP or another trade tier." },
    { label: "Assign First Trade Customer", done: dashboard.counts.assignments > 0, desc: "Link a customer to a pricing tier." },
    { label: "Add Specific Product Prices", done: dashboard.counts.overrides > 0 || !!dashboard.settings.reviewed_at, desc: "Create customer-specific price overrides where needed." },
    { label: "Review Configuration", done: !!dashboard.settings.reviewed_at, desc: "Confirm your tier and customer assignment setup is ready for testing." }
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

        ${dashboard.shop.plan_name === 'free' ? `<div style="padding:16px 18px;background:linear-gradient(135deg,#0b1f55,#1a3a8a);border-radius:18px;color:#fff;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
          <div>
            <div style="font-weight:700;font-size:15px;margin-bottom:4px;">You're on the Free plan — 1 tier, 1 customer.</div>
            <div style="font-size:13px;opacity:0.85;">Upgrade to Growth ($9/mo) for 3 tiers, 20 customers, and sitewide pricing — or Pro ($19/mo) for unlimited.</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <a href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=growth" style="background:rgba(255,255,255,0.15);color:#fff;font-weight:700;padding:10px 16px;border-radius:12px;text-decoration:none;font-size:14px;white-space:nowrap;border:1px solid rgba(255,255,255,0.3);">Growth — $9/mo</a>
            <a href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro" style="background:#fff;color:#0b1f55;font-weight:700;padding:10px 16px;border-radius:12px;text-decoration:none;font-size:14px;white-space:nowrap;">Pro — $19/mo</a>
          </div>
        </div>` : ''}
        ${dashboard.shop.plan_name === 'growth' ? `<div style="padding:16px 18px;background:linear-gradient(135deg,#0b4f6c,#0b7da0);border-radius:18px;color:#fff;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
          <div>
            <div style="font-weight:700;font-size:15px;margin-bottom:4px;">You're on the Growth plan — 3 tiers, 20 customers.</div>
            <div style="font-size:13px;opacity:0.85;">Upgrade to Pro ($19/mo) for unlimited tiers, CSV import, and scheduled pricing.</div>
          </div>
          <a href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro" style="background:#fff;color:#0b4f6c;font-weight:700;padding:10px 16px;border-radius:12px;text-decoration:none;font-size:14px;white-space:nowrap;">Upgrade to Pro — $19/mo</a>
        </div>` : ''}
        <div class="card">
          <h2>Onboarding checklist</h2>
          ${checklistHtml}
          ${!dashboard.settings.reviewed_at ? `<div class="actions" style="margin-top:4px;">
            <form method="post" action="/dashboard/mark-reviewed?shop=${encodeURIComponent(shop)}${host ? '&host=' + encodeURIComponent(host) : ''}">
              <button class="btn" type="submit">Mark as reviewed</button>
            </form>
          </div>` : ''}
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
          <div class="list">
            <div class="list-row">
              <div><strong>1. Create a Pricing Tier</strong></div>
              <div class="muted">Define a tier (e.g. Gold, Trade, VIP) with a percentage or fixed discount and optional date range.</div>
            </div>
            <div class="list-row">
              <div><strong>2. Assign Customers</strong></div>
              <div class="muted">Link a customer's email address to a tier. Free plan supports 1 customer; Premium is unlimited.</div>
            </div>
            <div class="list-row">
              <div><strong>3. Optional: Add Product Prices</strong></div>
              <div class="muted">Set exact fixed prices on specific products for a customer, overriding their tier discount.</div>
            </div>
            <div class="list-row">
              <div><strong>4. Enable the Theme Extension</strong></div>
              <div class="muted">Activate the PriceGuard block in your Shopify theme to display trade prices on product pages.</div>
            </div>
            <div class="list-row">
              <div><strong>5. Test with a Customer Account</strong></div>
              <div class="muted">Use the Pricing Preview tab to check prices before going live, then confirm in the storefront.</div>
            </div>
          </div>
          <div style="margin-top:14px;font-size:13px;color:#9ca3af;">
            Questions? Email <a href="mailto:support@sample-guard.com" style="color:#0b1f55;">support@sample-guard.com</a>
          </div>
        </div>

        <div class="card">
          <h2>Enable Theme Extension</h2>
          <div class="list">
            <div class="list-row">
              <div><strong>Step 1</strong></div>
              <div class="muted">In your Shopify admin, go to <strong>Online Store → Themes</strong></div>
            </div>
            <div class="list-row">
              <div><strong>Step 2</strong></div>
              <div class="muted">Click <strong>Customize</strong> on your active theme</div>
            </div>
            <div class="list-row">
              <div><strong>Step 3</strong></div>
              <div class="muted">In the theme editor, click <strong>Add section</strong> or <strong>Add block</strong></div>
            </div>
            <div class="list-row">
              <div><strong>Step 4</strong></div>
              <div class="muted">Search for <strong>PriceGuard</strong> and add the block to your product page template</div>
            </div>
            <div class="list-row">
              <div><strong>Step 5</strong></div>
              <div class="muted">For sitewide pricing (Growth/Pro), also enable the PriceGuard embed in <strong>Theme Settings → App Embeds</strong></div>
            </div>
          </div>
          <div style="margin-top:14px;">
            <a href="https://${escapeHtml(shop)}/admin/themes/current/editor" target="_blank" style="color:#0b1f55;font-weight:700;font-size:13px;">Open Theme Editor →</a>
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceGuard", content });
}

function renderPricingTiersPage({ shop, host, apiKey, dashboard, tiers, tierCount = 0, tierLimit = null }) {
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
          ${(() => {
            const limitReached = tierLimit !== null && tierCount >= tierLimit;
            const usageBadge = tierLimit !== null
              ? `<span style="float:right;font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px;background:${limitReached ? '#fef2f2' : '#f3f4f6'};color:${limitReached ? '#991b1b' : '#6b7280'}">${tierCount}/${tierLimit} tiers used</span>`
              : '';
            if (limitReached) {
              const isGrowth = dashboard.shop.plan_name === 'growth';
              const upgradeMsg = isGrowth
                ? 'You have reached the Growth plan limit of 3 tiers. Upgrade to Pro for unlimited tiers.'
                : 'You have reached the Free plan limit of 1 tier. Upgrade to Growth (3 tiers) or Pro (unlimited).';
              const upgradeActions = isGrowth
                ? `<a class="btn primary" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro">Upgrade to Pro — $19/mo</a>`
                : `<a class="btn primary" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=growth">Growth — $9/mo</a>
                   <a class="btn" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro">Pro — $19/mo</a>`;
              return `<h2>Create pricing tier ${usageBadge}</h2>
                <div class="empty" style="margin-bottom:12px;">${upgradeMsg}</div>
                <div class="actions">
                  ${upgradeActions}
                  <a class="btn" href="${getEmbeddedAppUrl(shop, host, '/')}">Back to dashboard</a>
                </div>`;
            }
            return `<h2>Create pricing tier ${usageBadge}</h2>
              <form method="post" action="/pricing-tiers?shop=${encodeURIComponent(shop)}${host ? '&host=' + encodeURIComponent(host) : ''}">
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
                  ${getPlanLimits(dashboard.shop.plan_name).scheduling ? `
                  <div class="field">
                    <label for="starts_at">Effective from</label>
                    <input id="starts_at" name="starts_at" type="datetime-local" />
                  </div>
                  <div class="field">
                    <label for="ends_at">Effective to</label>
                    <input id="ends_at" name="ends_at" type="datetime-local" />
                  </div>` : `
                  <div class="field full">
                    <div style="font-size:13px;color:#6b7280;padding:6px 0;">Scheduled pricing requires the <a href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro" style="color:#0b1f55;">Pro plan</a>.</div>
                  </div>`}
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
                  <a class="btn" href="${getEmbeddedAppUrl(shop, host, '/')}">Back to dashboard</a>
                </div>
              </form>`;
          })()}
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

function renderCustomerAssignmentsPage({ shop, host, apiKey, dashboard, tiers, assignments, tierCount = 0, tierLimit = null }) {
  const { customerLimit, scheduling } = getPlanLimits(dashboard.shop.plan_name);
  const distinctCustomerCount = new Set(assignments.map(a => a.customer_email)).size;
  const customerLimitReached = customerLimit !== null && distinctCustomerCount >= customerLimit;
  const customerUsageBadge = customerLimit !== null
    ? `<span style="float:right;font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px;background:${customerLimitReached ? '#fef2f2' : '#f3f4f6'};color:${customerLimitReached ? '#991b1b' : '#6b7280'}">${distinctCustomerCount}/${customerLimit} customers</span>`
    : '';

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
          <h2>Assign customer to tier ${customerUsageBadge}</h2>
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

              ${scheduling ? `
              <div class="field">
                <label for="starts_at">Effective from</label>
                <input id="starts_at" name="starts_at" type="datetime-local" />
              </div>
              <div class="field">
                <label for="ends_at">Effective to</label>
                <input id="ends_at" name="ends_at" type="datetime-local" />
              </div>` : `
              <div class="field full">
                <div style="font-size:13px;color:#6b7280;padding:6px 0;">Scheduled assignments require the <a href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro" style="color:#0b1f55;">Pro plan</a>.</div>
              </div>`}

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

// --- Cookie and session helpers ---

function getCookieValue(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    if (trimmed.slice(0, eq).trim() === name) {
      return decodeURIComponent(trimmed.slice(eq + 1));
    }
  }
  return null;
}

function signValue(value) {
  const secret = process.env.SHOPIFY_API_SECRET || "";
  return crypto.createHmac("sha256", secret).update(String(value)).digest("hex");
}

function makeSignedCookie(value) {
  return `${value}.${signValue(value)}`;
}

function readSignedCookie(raw) {
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot < 1) return null;
  const value = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = signValue(value);
  try {
    const a = Buffer.from(sig, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length) return null;
    return crypto.timingSafeEqual(a, b) ? value : null;
  } catch {
    return null;
  }
}

async function createAppSession(shopId, shopDomain) {
  const sessionKey = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await pool.query(
    `INSERT INTO app_sessions (shop_id, session_key, session_data, expires_at, created_at, updated_at)
     VALUES ($1, $2, $3::jsonb, $4, NOW(), NOW())`,
    [shopId, sessionKey, JSON.stringify({ shop_domain: shopDomain }), expiresAt]
  );
  return sessionKey;
}

async function requireShopSession(req, res, next) {
  const shop = sanitizeShop(req.query.shop);
  if (!shop) return res.status(400).send("Missing or invalid shop parameter.");

  const raw = getCookieValue(req, "pg_session");
  const sessionKey = readSignedCookie(raw);
  if (!sessionKey) return res.redirect(`/install?shop=${encodeURIComponent(shop)}`);

  try {
    const result = await pool.query(
      `SELECT s.expires_at, sh.shop_domain
       FROM app_sessions s
       JOIN shops sh ON sh.id = s.shop_id
       WHERE s.session_key = $1
       LIMIT 1`,
      [sessionKey]
    );

    if (result.rowCount === 0) {
      return res.redirect(`/install?shop=${encodeURIComponent(shop)}`);
    }

    const row = result.rows[0];

    if (new Date(row.expires_at) < new Date()) {
      await pool.query("DELETE FROM app_sessions WHERE session_key = $1", [sessionKey]);
      return res.redirect(`/install?shop=${encodeURIComponent(shop)}`);
    }

    if (row.shop_domain !== shop) {
      return res.status(403).send("Session shop mismatch.");
    }

    return next();
  } catch {
    return res.status(500).send("Session verification failed. Please try again.");
  }
}

async function requireShopSessionIfShop(req, res, next) {
  if (!sanitizeShop(req.query.shop)) return next();
  return requireShopSession(req, res, next);
}

// --- Routes ---

app.get("/", requireShopSessionIfShop, async (req, res) => {
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

app.get("/pricing-tiers", requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    if (!shop) return res.status(400).send("Missing or invalid shop.");

    const dashboard = await getDashboardData(shop);
    if (!dashboard) return res.status(404).send("Shop not found.");

    const tiers = await getPricingTiers(dashboard.shop.id);

    const tierCount = tiers.length;
    const { tierLimit } = getPlanLimits(dashboard.shop.plan_name);
    return res.send(renderPricingTiersPage({
      shop,
      host,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      dashboard,
      tiers,
      tierCount,
      tierLimit
    }));
  } catch (e) {
    return res.status(500).send(`Pricing Tiers load failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/pricing-tiers", requireShopSession, async (req, res) => {
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

    const limits = getPlanLimits(shopRow.plan_name);
    if (!limits.scheduling && (startsAt || endsAt)) {
      return res.status(403).send("Scheduled pricing (starts_at / ends_at) requires the Pro plan.");
    }
    const existingTierCount = await pool.query(
      `SELECT COUNT(*)::int AS count FROM pricing_tiers WHERE shop_id = $1`,
      [shopRow.id]
    );
    if (limits.tierLimit !== null && existingTierCount.rows[0].count >= limits.tierLimit) {
      return res.status(400).send(`Your plan is limited to ${limits.tierLimit} pricing tier(s). Upgrade to unlock more.`);
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

app.post("/pricing-tiers/:id/toggle", requireShopSession, async (req, res) => {
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

app.post("/pricing-tiers/:id/delete", requireShopSession, async (req, res) => {
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


app.get("/customer-assignments", requireShopSession, async (req, res) => {
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

    const tierCount = tiers.length;
    const { tierLimit } = getPlanLimits(dashboard.shop.plan_name);
    return res.send(renderCustomerAssignmentsPage({
      shop,
      host,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      dashboard,
      tiers,
      assignments,
      tierCount,
      tierLimit,
      prefillEmail: useEmail,
      prefillId: useId
    }));
  } catch (e) {
    return res.status(500).send(`Customer Assignments load failed: ${escapeHtml(e.message)}`);
  }
});

app.post("/customer-assignments", requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    if (!shop) return res.status(400).send("Missing or invalid shop.");

    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send("Shop not found.");

    const { customerLimit: limit } = getPlanLimits(shopRow.plan_name);

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

    if (isNewCustomer && limit !== null && currentDistinct >= limit) {
      return res.status(400).send(`Customer limit reached. Your plan allows ${limit} trade customer(s). Upgrade to unlock more.`);
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

app.post("/customer-assignments/:id/toggle", requireShopSession, async (req, res) => {
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

app.post("/customer-assignments/:id/delete", requireShopSession, async (req, res) => {
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


// --- Customer Product Prices ---

function extractCsvFromMultipart(contentType, buf) {
  const m = /boundary=([^\s;]+)/i.exec(contentType || '');
  if (!m) return buf.toString('utf8');
  const boundary = m[1].replace(/^"(.*)"$/, '$1');
  const sep = '--' + boundary;
  const first = buf.indexOf(Buffer.from(sep + '\r\n'));
  if (first === -1) return buf.toString('utf8');
  const afterSep = first + sep.length + 2;
  const headerEnd = buf.indexOf(Buffer.from('\r\n\r\n'), afterSep);
  if (headerEnd === -1) return '';
  const bodyStart = headerEnd + 4;
  const terminator = buf.indexOf(Buffer.from('\r\n--' + boundary), bodyStart);
  return (terminator === -1 ? buf.slice(bodyStart) : buf.slice(bodyStart, terminator)).toString('utf8');
}

app.get('/customer-product-prices', requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || '');
    if (!shop) return res.status(400).send('Missing or invalid shop.');
    const dashboard = await getDashboardData(shop);
    if (!dashboard) return res.status(404).send('Shop not found.');
    const shopId = dashboard.shop.id;
    const { skuOverrides, csvImport } = getPlanLimits(dashboard.shop.plan_name);
    const page = Math.max(1, Number(req.query.page) || 1);
    const perPage = 25;
    const search = String(req.query.search || '').trim();
    const offset = (page - 1) * perPage;

    let countQ, rowsQ;
    if (search) {
      const like = '%' + search.toLowerCase() + '%';
      countQ = await pool.query(
        `SELECT COUNT(*)::int AS count FROM customer_product_prices WHERE shop_id=$1 AND (LOWER(customer_email) LIKE $2 OR LOWER(COALESCE(sku,'')) LIKE $2)`,
        [shopId, like]
      );
      rowsQ = await pool.query(
        `SELECT id, customer_email, product_id, sku, fixed_price, currency, starts_at, ends_at, is_enabled FROM customer_product_prices WHERE shop_id=$1 AND (LOWER(customer_email) LIKE $2 OR LOWER(COALESCE(sku,'')) LIKE $2) ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`,
        [shopId, like, perPage, offset]
      );
    } else {
      countQ = await pool.query(
        `SELECT COUNT(*)::int AS count FROM customer_product_prices WHERE shop_id=$1`, [shopId]
      );
      rowsQ = await pool.query(
        `SELECT id, customer_email, product_id, sku, fixed_price, currency, starts_at, ends_at, is_enabled FROM customer_product_prices WHERE shop_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`,
        [shopId, perPage, offset]
      );
    }

    const totalCount = countQ.rows[0].count;
    const totalPages = Math.ceil(totalCount / perPage) || 1;
    const rows = rowsQ.rows;
    const baseUrl = getEmbeddedAppUrl(shop, host, '/customer-product-prices');

    const tableRows = rows.length === 0
      ? `<tr><td colspan="8" class="muted" style="text-align:center;padding:20px;">No rows yet.</td></tr>`
      : rows.map(r => `
          <tr>
            <td>${escapeHtml(r.customer_email)}</td>
            <td>${escapeHtml(r.product_id || '—')}</td>
            <td>${escapeHtml(r.sku || '—')}</td>
            <td><strong>£${Number(r.fixed_price).toFixed(2)}</strong></td>
            <td>${escapeHtml(r.currency || 'GBP')}</td>
            <td>${escapeHtml(fmtDisplayDate(r.starts_at))}</td>
            <td>${escapeHtml(fmtDisplayDate(r.ends_at))}</td>
            <td>
              <form class="inline-form" method="post" action="/customer-product-prices/${r.id}/delete?shop=${encodeURIComponent(shop)}${host ? '&host=' + encodeURIComponent(host) : ''}" onsubmit="return confirm('Delete this price override?');">
                <button class="btn small danger" type="submit">Delete</button>
              </form>
            </td>
          </tr>`).join('');

    const pagination = totalPages > 1
      ? `<div style="margin-top:12px;display:flex;gap:8px;align-items:center;">
          ${page > 1 ? `<a class="btn small" href="${baseUrl}&page=${page - 1}${search ? '&search=' + encodeURIComponent(search) : ''}">Previous</a>` : ''}
          <span class="muted">Page ${page} of ${totalPages} (${totalCount} rows)</span>
          ${page < totalPages ? `<a class="btn small" href="${baseUrl}&page=${page + 1}${search ? '&search=' + encodeURIComponent(search) : ''}">Next</a>` : ''}
        </div>`
      : `<div class="muted" style="margin-top:8px;font-size:13px;">${totalCount} row${totalCount !== 1 ? 's' : ''}</div>`;

    const importedMsg = req.query.imported ? `<div style="margin-bottom:12px;padding:10px 14px;background:#ecfdf5;border-radius:12px;color:#065f46;font-weight:600;">${escapeHtml(req.query.imported)} row(s) imported${req.query.skipped ? ', ' + escapeHtml(req.query.skipped) + ' skipped' : ''}.</div>` : '';

    const content = `
      ${renderBrandHero({ shop, host, planName: dashboard.shop.plan_name || 'free', statusText: 'Price Overrides', title: 'Customer Product Prices', subtitle: 'Set fixed prices for specific customers on specific products, overriding tier discounts.', active: 'prices' })}
      <div class="grid">
        <div class="stack">
          <div class="card">
            <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap;">
              <h2 style="margin:0;">Price Overrides</h2>
              <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <a class="btn small" href="${getEmbeddedAppUrl(shop, host, '/customer-product-prices/export.csv')}">Export CSV</a>
                ${csvImport ? `<button class="btn small primary" onclick="document.getElementById('pg-import-form').style.display='block'">Import CSV</button>` : ''}
              </div>
            </div>
            ${importedMsg}
            ${csvImport ? `
            <div id="pg-import-form" style="display:none;margin-bottom:16px;padding:14px;border:1px solid var(--line);border-radius:14px;">
              <form method="post" action="/customer-product-prices/import?shop=${encodeURIComponent(shop)}${host ? '&host=' + encodeURIComponent(host) : ''}" enctype="multipart/form-data">
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                  <input type="file" name="file" accept=".csv,text/csv" required style="flex:1;" />
                  <button class="btn small primary" type="submit">Upload</button>
                  <button class="btn small" type="button" onclick="document.getElementById('pg-import-form').style.display='none'">Cancel</button>
                </div>
                <div class="muted" style="margin-top:8px;font-size:12px;">CSV columns: customer_email, product_id, sku, fixed_price, currency, starts_at, ends_at, is_enabled</div>
              </form>
            </div>` : ''}
            <form style="margin-bottom:12px;display:flex;gap:8px;" onsubmit="event.preventDefault(); window.location.href='${baseUrl}&search=' + encodeURIComponent(this.querySelector('[name=search]').value);">
              <input name="search" value="${escapeHtml(search)}" placeholder="Search by email or SKU…" style="flex:1;padding:8px 12px;border:1px solid var(--line);border-radius:12px;" />
              <button class="btn small" type="submit">Search</button>
              ${search ? `<a class="btn small" href="${baseUrl}">Clear</a>` : ''}
            </form>
            <table>
              <thead><tr><th>Email</th><th>Product ID</th><th>SKU</th><th>Fixed Price</th><th>Currency</th><th>From</th><th>To</th><th>Actions</th></tr></thead>
              <tbody>${tableRows}</tbody>
            </table>
            ${pagination}
          </div>
        </div>

        <div class="stack">
          ${skuOverrides ? `
          <div class="card">
            <h2>Add price override</h2>
            <form method="post" action="/customer-product-prices?shop=${encodeURIComponent(shop)}${host ? '&host=' + encodeURIComponent(host) : ''}">
              <div class="form-grid">
                <div class="field full"><label>Customer email</label><input name="customer_email" type="email" placeholder="buyer@example.com" required /></div>
                <div class="field"><label>Product ID</label><input name="product_id" placeholder="12345678" /></div>
                <div class="field"><label>SKU</label><input name="sku" placeholder="PROD-001" /></div>
                <div class="field"><label>Fixed price</label><input name="fixed_price" type="number" step="0.01" min="0" placeholder="19.99" required /></div>
                <div class="field"><label>Currency</label><input name="currency" placeholder="GBP" value="GBP" /></div>
                <div class="field"><label>Effective from</label><input name="starts_at" type="datetime-local" /></div>
                <div class="field"><label>Effective to</label><input name="ends_at" type="datetime-local" /></div>
                <div class="field full"><label>Status</label><select name="is_enabled"><option value="true">Enabled</option><option value="false">Disabled</option></select></div>
              </div>
              <div class="actions"><button class="btn primary" type="submit">Create override</button><a class="btn" href="${getEmbeddedAppUrl(shop, host, '/')}">Back</a></div>
            </form>
          </div>` : `
          <div class="card">
            <h2>Growth / Pro feature</h2>
            <div class="muted">Customer product price overrides require the Growth or Pro plan.</div>
            <div class="actions" style="margin-top:12px;">
              <a class="btn primary" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=growth">Growth — $9/mo</a>
              <a class="btn" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro">Pro — $19/mo</a>
            </div>
          </div>`}
          <div class="card">
            <h2>How it works</h2>
            <div class="list">
              <div class="list-row"><div>Fixed price</div><div class="muted">Overrides tier discount for this customer + product</div></div>
              <div class="list-row"><div>Date range</div><div class="muted">Optional — leave blank for always-on</div></div>
              <div class="list-row"><div>CSV import</div><div class="muted">Bulk load prices (Pro plan only)</div></div>
            </div>
          </div>
        </div>
      </div>
    `;

    return res.send(renderLayout({ shop, host, apiKey: process.env.SHOPIFY_API_KEY || '', title: 'PriceGuard | Price Overrides', content }));
  } catch (e) {
    return res.status(500).send(`Customer product prices load failed: ${escapeHtml(e.message)}`);
  }
});

app.get('/customer-product-prices/export.csv', requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    if (!shop) return res.status(400).send('Missing or invalid shop.');
    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send('Shop not found.');

    const result = await pool.query(
      `SELECT customer_email, product_id, sku, fixed_price, currency, starts_at, ends_at, is_enabled FROM customer_product_prices WHERE shop_id=$1 ORDER BY created_at DESC, id DESC`,
      [shopRow.id]
    );

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="customer_product_prices.csv"');
    res.write('customer_email,product_id,sku,fixed_price,currency,starts_at,ends_at,is_enabled\n');
    for (const r of result.rows) {
      const cols = [r.customer_email, r.product_id || '', r.sku || '', r.fixed_price, r.currency || 'GBP', r.starts_at ? new Date(r.starts_at).toISOString() : '', r.ends_at ? new Date(r.ends_at).toISOString() : '', r.is_enabled ? '1' : '0'];
      res.write(cols.map(v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"').join(',') + '\n');
    }
    res.end();
  } catch (e) {
    return res.status(500).send(`Export failed: ${escapeHtml(e.message)}`);
  }
});

app.post('/customer-product-prices', requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || '');
    if (!shop) return res.status(400).send('Missing or invalid shop.');
    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send('Shop not found.');
    if (!getPlanLimits(shopRow.plan_name).skuOverrides) return res.status(403).send('Customer product price overrides require the Growth or Pro plan.');

    const customerEmail = String(req.body.customer_email || '').trim().toLowerCase();
    const productId = String(req.body.product_id || '').trim() || null;
    const sku = String(req.body.sku || '').trim() || null;
    const currency = String(req.body.currency || 'GBP').trim() || 'GBP';
    const startsAt = String(req.body.starts_at || '').trim() || null;
    const endsAt = String(req.body.ends_at || '').trim() || null;
    const isEnabled = String(req.body.is_enabled || 'true') === 'true';
    const fixedPrice = Number(String(req.body.fixed_price || '').trim());

    if (!customerEmail) return res.status(400).send('Customer email is required.');
    if (!Number.isFinite(fixedPrice) || fixedPrice < 0) return res.status(400).send('Fixed price must be a valid non-negative number.');

    const ins = await pool.query(
      `INSERT INTO customer_product_prices (shop_id, customer_email, product_id, sku, fixed_price, currency, starts_at, ends_at, is_enabled, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, $9, NOW(), NOW())
       RETURNING id`,
      [shopRow.id, customerEmail, productId, sku, fixedPrice, currency, startsAt, endsAt, isEnabled]
    );
    await writeAudit(shopRow.id, 'customer_product_price_created', 'customer_product_price', ins.rows[0].id, { customer_email: customerEmail, product_id: productId, sku, fixed_price: fixedPrice });
    return res.redirect(getEmbeddedAppUrl(shop, host, '/customer-product-prices'));
  } catch (e) {
    return res.status(500).send(`Create customer product price failed: ${escapeHtml(e.message)}`);
  }
});

app.post('/customer-product-prices/import', requireShopSession, express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || '');
    if (!shop) return res.status(400).send('Missing or invalid shop.');
    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send('Shop not found.');
    if (!getPlanLimits(shopRow.plan_name).csvImport) return res.status(403).send('CSV import requires the Pro plan.');

    const contentType = req.get('content-type') || '';
    let csvText;
    if (contentType.includes('multipart/form-data')) {
      csvText = extractCsvFromMultipart(contentType, req.body);
    } else {
      csvText = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body || '');
    }

    const lines = csvText.split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length < 2) return res.status(400).send('CSV must have a header row and at least one data row.');

    const header = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/^"|"$/g, ''));
    const emailIdx = header.indexOf('customer_email');
    const productIdx = header.indexOf('product_id');
    const skuIdx = header.indexOf('sku');
    const priceIdx = header.indexOf('fixed_price');
    const currencyIdx = header.indexOf('currency');
    const startsIdx = header.indexOf('starts_at');
    const endsIdx = header.indexOf('ends_at');
    const enabledIdx = header.indexOf('is_enabled');

    if (emailIdx === -1 || priceIdx === -1) return res.status(400).send('CSV must include customer_email and fixed_price columns.');

    let imported = 0;
    let skipped = 0;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (let i = 1; i < lines.length; i++) {
        const cols = lines[i].split(',').map(c => c.trim().replace(/^"|"$/g, ''));
        const customerEmail = (cols[emailIdx] || '').toLowerCase().trim();
        if (!customerEmail) { skipped++; continue; }
        const fixedPrice = Number(cols[priceIdx] || '');
        if (!Number.isFinite(fixedPrice) || fixedPrice < 0) { skipped++; continue; }
        const productId = productIdx !== -1 ? (cols[productIdx] || null) : null;
        const sku = skuIdx !== -1 ? (cols[skuIdx] || null) : null;
        const currency = currencyIdx !== -1 ? (cols[currencyIdx] || 'GBP') : 'GBP';
        const startsAt = startsIdx !== -1 ? (cols[startsIdx] || null) : null;
        const endsAt = endsIdx !== -1 ? (cols[endsIdx] || null) : null;
        const rawEnabled = enabledIdx !== -1 ? cols[enabledIdx] : '1';
        const isEnabled = rawEnabled !== '0' && rawEnabled.toLowerCase() !== 'false';

        if (productId) {
          await client.query(
            `DELETE FROM customer_product_prices WHERE shop_id=$1 AND LOWER(customer_email)=$2 AND product_id=$3`,
            [shopRow.id, customerEmail, productId]
          );
        }
        await client.query(
          `INSERT INTO customer_product_prices (shop_id, customer_email, product_id, sku, fixed_price, currency, starts_at, ends_at, is_enabled, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::timestamptz, $9, NOW(), NOW())`,
          [shopRow.id, customerEmail, productId, sku, fixedPrice, currency, startsAt || null, endsAt || null, isEnabled]
        );
        imported++;
      }
      await client.query('COMMIT');
    } catch (importErr) {
      await client.query('ROLLBACK');
      throw importErr;
    } finally {
      client.release();
    }

    await writeAudit(shopRow.id, 'customer_product_prices_imported', 'customer_product_prices', shopRow.id, { imported, skipped });
    return res.redirect(getEmbeddedAppUrl(shop, host, '/customer-product-prices') + '&imported=' + imported + '&skipped=' + skipped);
  } catch (e) {
    return res.status(500).send(`Import failed: ${escapeHtml(e.message)}`);
  }
});

app.post('/customer-product-prices/:id/delete', requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || '');
    const id = Number(req.params.id);
    if (!shop || !Number.isFinite(id)) return res.status(400).send('Invalid request.');
    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send('Shop not found.');

    const current = await pool.query(
      `SELECT id, customer_email FROM customer_product_prices WHERE id=$1 AND shop_id=$2 LIMIT 1`,
      [id, shopRow.id]
    );
    if (current.rowCount === 0) return res.status(404).send('Price override not found.');

    await pool.query(`DELETE FROM customer_product_prices WHERE id=$1 AND shop_id=$2`, [id, shopRow.id]);
    await writeAudit(shopRow.id, 'customer_product_price_deleted', 'customer_product_price', id, { customer_email: current.rows[0].customer_email });
    return res.redirect(getEmbeddedAppUrl(shop, host, '/customer-product-prices'));
  } catch (e) {
    return res.status(500).send(`Delete customer product price failed: ${escapeHtml(e.message)}`);
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


app.get("/pricing-preview", requireShopSession, async (req, res) => {
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
    const shopDomain = req.get("X-Shopify-Shop-Domain") || "";
    const customerEmail = String(payload.customer?.email || "").trim().toLowerCase();
    const customerId = String(payload.customer?.id || "");
    const callbackUrl = String(payload.data_request?.callback_url || "");

    const shopRes = await pool.query(
      `SELECT id, access_token FROM shops WHERE shop_domain = $1 LIMIT 1`,
      [shopDomain]
    );

    if (shopRes.rowCount === 0 || !callbackUrl) {
      return res.status(200).send("OK");
    }

    const shop = shopRes.rows[0];

    const [assignmentsRes, pricesRes] = await Promise.all([
      pool.query(
        `SELECT id, customer_email, shopify_customer_id, tier_id, starts_at, ends_at, is_enabled, created_at
         FROM customer_assignments
         WHERE shop_id = $1
           AND (LOWER(customer_email) = $2 OR shopify_customer_id = $3)`,
        [shop.id, customerEmail, customerId]
      ),
      pool.query(
        `SELECT id, customer_email, shopify_customer_id, product_id, variant_id, sku, fixed_price, currency, starts_at, ends_at, is_enabled, created_at
         FROM customer_product_prices
         WHERE shop_id = $1
           AND (LOWER(customer_email) = $2 OR shopify_customer_id = $3)`,
        [shop.id, customerEmail, customerId]
      )
    ]);

    const exportData = {
      customer: payload.customer,
      data_request_id: payload.data_request?.id,
      customer_assignments: assignmentsRes.rows,
      customer_product_prices: pricesRes.rows
    };

    if (shop.access_token) {
      await fetch(callbackUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${shop.access_token}`
        },
        body: JSON.stringify(exportData)
      }).catch((e) => console.error("[GDPR data_request] callback POST failed", e.message));
    }

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
    const shopDomain = req.get("X-Shopify-Shop-Domain") || "";
    const customerEmail = String(payload.customer?.email || "").trim().toLowerCase();
    const customerId = String(payload.customer?.id || "");

    const shopRes = await pool.query(
      `SELECT id FROM shops WHERE shop_domain = $1 LIMIT 1`,
      [shopDomain]
    );

    if (shopRes.rowCount === 0) {
      return res.status(200).send("OK");
    }

    const shopId = shopRes.rows[0].id;

    const assignmentsDel = await pool.query(
      `DELETE FROM customer_assignments
       WHERE shop_id = $1
         AND (LOWER(customer_email) = $2 OR shopify_customer_id = $3)
       RETURNING id`,
      [shopId, customerEmail, customerId]
    );

    const pricesDel = await pool.query(
      `DELETE FROM customer_product_prices
       WHERE shop_id = $1
         AND (LOWER(customer_email) = $2 OR shopify_customer_id = $3)
       RETURNING id`,
      [shopId, customerEmail, customerId]
    );

    await pool.query(
      `INSERT INTO audit_logs (shop_id, actor_type, actor_email, action, entity_type, entity_id, metadata_json)
       VALUES ($1, 'system', 'shopify-gdpr', 'gdpr_customer_redact', 'customer', $2, $3::jsonb)`,
      [shopId, customerId || customerEmail, JSON.stringify({
        customer_email: customerEmail,
        customer_id: customerId,
        assignments_deleted: assignmentsDel.rowCount,
        prices_deleted: pricesDel.rowCount
      })]
    );

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
    const shopDomain = req.get("X-Shopify-Shop-Domain") || String(payload.domain || "");

    const shopRes = await pool.query(
      `SELECT id FROM shops WHERE shop_domain = $1 LIMIT 1`,
      [shopDomain]
    );

    if (shopRes.rowCount === 0) {
      return res.status(200).send("OK");
    }

    const shopId = shopRes.rows[0].id;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM audit_logs WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM imports WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM collection_rules WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM customer_product_prices WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM customer_assignments WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM pricing_tiers WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM app_sessions WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM settings WHERE shop_id = $1", [shopId]);
      await client.query("DELETE FROM shops WHERE id = $1", [shopId]);
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }

    return res.status(200).send("OK");
  } catch (err) {
    console.error("[SHOPIFY_COMPLIANCE] shop/redact failed", err);
    return res.status(200).send("OK");
  }
});



app.post("/webhooks/app/uninstalled", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!verifyShopifyWebhookHmac(req)) {
      return res.status(400).send("Invalid webhook signature");
    }

    const shopDomain = req.get("X-Shopify-Shop-Domain") || "";
    if (!shopDomain) return res.status(200).send("OK");

    const shopRes = await pool.query(
      `UPDATE shops
       SET uninstalled_at = NOW(), access_token = NULL,
           plan_name = 'free', plan_status = 'inactive', updated_at = NOW()
       WHERE shop_domain = $1
       RETURNING id`,
      [shopDomain]
    );

    if (shopRes.rowCount > 0) {
      const shopId = shopRes.rows[0].id;
      await pool.query("DELETE FROM app_sessions WHERE shop_id = $1", [shopId]);
    }

    return res.status(200).send("OK");
  } catch (err) {
    console.error("[SHOPIFY_WEBHOOK] app/uninstalled failed", err);
    return res.status(200).send("OK");
  }
});



function verifyPriceGuardAppProxySignature(query) {
  const secret = process.env.SHOPIFY_API_SECRET || "";
  const signature = String(query.signature || "");
  if (!secret || !signature) return false;

  const params = { ...query };
  delete params.signature;

  const message = Object.keys(params)
    .sort()
    .map((key) => {
      const value = Array.isArray(params[key]) ? params[key].join(",") : String(params[key] ?? "");
      return `${key}=${value}`;
    })
    .join("");

  const digest = crypto
    .createHmac("sha256", secret)
    .update(message)
    .digest("hex");

  try {
    const a = Buffer.from(digest, "utf8");
    const b = Buffer.from(signature, "utf8");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

async function getPriceGuardShopByDomain(shopDomain) {
  const res = await pool.query(
    `SELECT id, shop_domain, access_token, plan_name
     FROM shops
     WHERE shop_domain = $1
     LIMIT 1`,
    [shopDomain]
  );
  return res.rows[0] || null;
}

async function getPriceGuardAssignmentByShopifyCustomerId(shopId, shopifyCustomerId) {
  const res = await pool.query(
    `SELECT
       ca.id,
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
       AND ca.shopify_customer_id = $2
     ORDER BY ca.created_at DESC, ca.id DESC
     LIMIT 1`,
    [shopId, String(shopifyCustomerId)]
  );
  return res.rows[0] || null;
}


async function getPriceGuardTierByCustomerTags(shopId, tags) {
  const cleaned = Array.isArray(tags)
    ? tags.map((t) => String(t || "").trim().toLowerCase()).filter(Boolean)
    : [];

  if (!cleaned.length) return null;

  const res = await pool.query(
    `SELECT
       pt.id AS tier_id,
       pt.name AS tier_name,
       pt.customer_tag,
       pt.discount_type,
       pt.discount_value,
       pt.starts_at AS tier_starts_at,
       pt.ends_at AS tier_ends_at,
       pt.is_enabled AS tier_enabled
     FROM pricing_tiers pt
     WHERE pt.shop_id = $1
       AND LOWER(COALESCE(pt.customer_tag, '')) = ANY($2::text[])
     ORDER BY pt.created_at DESC, pt.id DESC
     LIMIT 1`,
    [shopId, cleaned]
  );

  return res.rows[0] || null;
}

async function getPriceGuardAssignmentByEmail(shopId, email) {
  const res = await pool.query(
    `SELECT
       ca.id,
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
    [shopId, email]
  );
  return res.rows[0] || null;
}

function isPriceGuardRuleLive(startsAt, endsAt, isEnabled) {
  if (!isEnabled) return false;
  const now = new Date();

  if (startsAt && new Date(startsAt) > now) return false;
  if (endsAt && new Date(endsAt) < now) return false;

  return true;
}

async function refreshShopToken(shopDomain) {
  const shopRes = await pool.query(
    `SELECT id, refresh_token FROM shops WHERE shop_domain = $1 LIMIT 1`,
    [shopDomain]
  );
  const shop = shopRes.rows[0];
  if (!shop || !shop.refresh_token) {
    throw new Error(`No refresh token available for ${shopDomain}`);
  }

  const res = await fetch(`https://${shopDomain}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.SHOPIFY_API_KEY,
      client_secret: process.env.SHOPIFY_API_SECRET,
      grant_type: "refresh_token",
      refresh_token: shop.refresh_token
    })
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token refresh failed: ${res.status} ${text}`);
  }

  const json = await res.json();
  const newAccessToken = json.access_token;
  const newRefreshToken = json.refresh_token || shop.refresh_token;
  const expiresIn = json.expires_in || 3600;
  const tokenExpiresAt = new Date(Date.now() + expiresIn * 1000);

  await pool.query(
    `UPDATE shops SET access_token = $1, refresh_token = $2, token_expires_at = $3, updated_at = NOW() WHERE id = $4`,
    [newAccessToken, newRefreshToken, tokenExpiresAt, shop.id]
  );

  return newAccessToken;
}

async function priceGuardShopifyAdminGraphQL(shopDomain, accessToken, query, variables = {}) {
  const shopRes = await pool.query(
    `SELECT token_expires_at FROM shops WHERE shop_domain = $1 LIMIT 1`,
    [shopDomain]
  );
  const shopRow = shopRes.rows[0];
  if (shopRow && shopRow.token_expires_at) {
    const expiresAt = new Date(shopRow.token_expires_at);
    if (expiresAt <= new Date(Date.now() + 5 * 60 * 1000)) {
      accessToken = await refreshShopToken(shopDomain);
    }
  }

  const response = await fetch(`https://${shopDomain}/admin/api/2026-04/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!response.ok) {
    throw new Error(`Shopify Admin GraphQL failed with ${response.status}`);
  }

  const json = await response.json();
  if (json.errors?.length) {
    throw new Error(JSON.stringify(json.errors));
  }

  return json.data;
}

async function getPriceGuardShopifyCustomerBasic(shopDomain, accessToken, customerId) {
  const data = await priceGuardShopifyAdminGraphQL(
    shopDomain,
    accessToken,
    `#graphql
    query PriceGuardCustomer($id: ID!) {
      customer(id: $id) {
        id
        email
        firstName
        lastName
      }
    }`,
    { id: `gid://shopify/Customer/${customerId}` }
  );

  return data.customer || null;
}

async function getPriceGuardProductPricingContext(shopDomain, accessToken, productId) {
  const data = await priceGuardShopifyAdminGraphQL(
    shopDomain,
    accessToken,
    `#graphql
    query PriceGuardProduct($id: ID!) {
      product(id: $id) {
        id
        title
        handle
        featuredImage {
          url
        }
        variants(first: 1) {
          nodes {
            id
            price
            compareAtPrice
          }
        }
        priceRangeV2 {
          minVariantPrice {
            amount
            currencyCode
          }
          maxVariantPrice {
            amount
            currencyCode
          }
        }
      }
    }`,
    { id: `gid://shopify/Product/${productId}` }
  );

  return data.product || null;
}

function calculatePriceGuardDisplayPrice(baseAmount, discountType, discountValue) {
  const base = Number(baseAmount || 0);
  const value = Number(discountValue || 0);

  if (!base || !value) return base;

  if (discountType === "percentage") {
    return Math.max(0, +(base * (1 - value / 100)).toFixed(2));
  }

  if (discountType === "fixed_amount") {
    return Math.max(0, +(base - value).toFixed(2));
  }

  return base;
}

async function resolvePriceGuardAssignment(shop, loggedInCustomerId, customerTags = [], customerEmail = "") {
  let assignment = await getPriceGuardAssignmentByShopifyCustomerId(shop.id, loggedInCustomerId);
  if (assignment) {
    return { assignment, customerEmail: assignment.customer_email || customerEmail || "" };
  }

  if (customerEmail) {
    assignment = await getPriceGuardAssignmentByEmail(shop.id, customerEmail);
    if (assignment) {
      return { assignment, customerEmail };
    }
  }

  const tier = await getPriceGuardTierByCustomerTags(shop.id, customerTags);
  if (!tier) {
    return { assignment: null, customerEmail };
  }

  return {
    assignment: {
      customer_email: customerEmail || "",
      shopify_customer_id: String(loggedInCustomerId || ""),
      assignment_starts_at: null,
      assignment_ends_at: null,
      assignment_enabled: true,
      tier_id: tier.tier_id,
      tier_name: tier.tier_name,
      customer_tag: tier.customer_tag,
      discount_type: tier.discount_type,
      discount_value: tier.discount_value,
      tier_starts_at: tier.tier_starts_at,
      tier_ends_at: tier.tier_ends_at,
      tier_enabled: tier.tier_enabled
    },
    customerEmail
  };
}

app.get("/proxy/price", async (req, res) => {
  try {
    const query = req.query || {};

    if (!verifyPriceGuardAppProxySignature(query)) {
      return res.status(400).json({ ok: false, error: "Invalid app proxy signature" });
    }

    const shopDomain = String(query.shop || "").trim();
    const loggedInCustomerId = String(query.logged_in_customer_id || "").trim();
    const productId = String(query.product_id || "").trim();
    const customerEmail = String(query.customer_email || "").trim();
    const customerTags = String(query.customer_tags || "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

    if (!shopDomain || !productId) {
      return res.status(400).json({ ok: false, error: "Missing shop or product_id" });
    }

    if (!loggedInCustomerId) {
      return res.json({
        ok: true,
        logged_in: false,
        has_assignment: false,
        product_id: productId
      });
    }

    const shop = await getPriceGuardShopByDomain(shopDomain);
    if (!shop || !shop.access_token) {
      return res.status(404).json({ ok: false, error: "Shop not found" });
    }

    const { assignment, customerEmail: resolvedCustomerEmail } = await resolvePriceGuardAssignment(
      shop,
      loggedInCustomerId,
      customerTags,
      customerEmail
    );
    if (!assignment) {
      return res.json({
        ok: true,
        logged_in: true,
        has_assignment: false,
        product_id: productId,
        customer_id: loggedInCustomerId,
        customer_email: resolvedCustomerEmail
      });
    }

    const assignmentLive = isPriceGuardRuleLive(
      assignment.assignment_starts_at,
      assignment.assignment_ends_at,
      assignment.assignment_enabled
    );
    const tierLive = isPriceGuardRuleLive(
      assignment.tier_starts_at,
      assignment.tier_ends_at,
      assignment.tier_enabled
    );

    if (!assignmentLive || !tierLive) {
      return res.json({
        ok: true,
        logged_in: true,
        has_assignment: true,
        active: false,
        product_id: productId,
        customer_id: loggedInCustomerId,
        customer_email: resolvedCustomerEmail || assignment.customer_email || "",
        tier_name: assignment.tier_name
      });
    }

    const skuPriceRes = await pool.query(
      `SELECT fixed_price FROM customer_product_prices
       WHERE shop_id = $1 AND LOWER(customer_email) = LOWER($2) AND product_id = $3
         AND is_enabled = true
         AND (starts_at IS NULL OR starts_at <= NOW())
         AND (ends_at IS NULL OR ends_at >= NOW())
       ORDER BY id DESC LIMIT 1`,
      [shop.id, resolvedCustomerEmail || assignment.customer_email || '', productId]
    );
    const skuFixedPrice = skuPriceRes.rowCount > 0 ? Number(skuPriceRes.rows[0].fixed_price) : null;

    const product = await getPriceGuardProductPricingContext(shop.shop_domain, shop.access_token, productId);
    if (!product) {
      return res.status(404).json({ ok: false, error: "Product not found" });
    }

    const firstVariant = product.variants?.nodes?.[0] || null;
    const basePrice = Number(firstVariant?.price || product.priceRangeV2?.minVariantPrice?.amount || 0);
    const compareAt = firstVariant?.compareAtPrice ? Number(firstVariant.compareAtPrice) : null;
    const finalPrice = skuFixedPrice !== null
      ? skuFixedPrice
      : calculatePriceGuardDisplayPrice(basePrice, assignment.discount_type, assignment.discount_value);

    return res.json({
      ok: true,
      logged_in: true,
      has_assignment: true,
      active: true,
      product_id: productId,
      customer_id: loggedInCustomerId,
      customer_email: resolvedCustomerEmail || assignment.customer_email || "",
      product_title: product.title,
      handle: product.handle,
      currency_code: product.priceRangeV2?.minVariantPrice?.currencyCode || "GBP",
      tier_name: assignment.tier_name,
      discount_type: assignment.discount_type,
      discount_value: Number(assignment.discount_value),
      base_price: basePrice,
      compare_at_price: compareAt,
      final_price: finalPrice
    });
  } catch (err) {
    console.error("[PRICEGUARD_PROXY_PRICE] failed", err);
    return res.status(500).json({ ok: false, error: "Price resolution failed" });
  }
});


app.get("/proxy/prices", async (req, res) => {
  try {
    const query = req.query || {};

    if (!verifyPriceGuardAppProxySignature(query)) {
      return res.status(400).json({ ok: false, error: "Invalid app proxy signature" });
    }

    const shopDomain = String(query.shop || "").trim();
    const loggedInCustomerId = String(query.logged_in_customer_id || "").trim();
    const customerEmail = String(query.customer_email || "").trim();
    const customerTags = String(query.customer_tags || "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

    const productIds = String(query.product_ids || "")
      .split(",")
      .map((id) => id.trim())
      .filter((id) => /^\d+$/.test(id))
      .slice(0, 50);

    if (!shopDomain || productIds.length === 0) {
      return res.status(400).json({ ok: false, error: "Missing shop or product_ids" });
    }

    if (!loggedInCustomerId) {
      return res.json({ ok: false, logged_in: false });
    }

    const shop = await getPriceGuardShopByDomain(shopDomain);
    if (!shop || !shop.access_token) {
      return res.status(404).json({ ok: false, error: "Shop not found" });
    }

    if (!getPlanLimits(shop.plan_name).skuOverrides) {
      const result = {};
      for (const id of productIds) result[id] = { ok: false, active: false, reason: "sitewide_plan_required" };
      return res.json(result);
    }

    const { assignment } = await resolvePriceGuardAssignment(
      shop,
      loggedInCustomerId,
      customerTags,
      customerEmail
    );

    if (!assignment) {
      const result = {};
      for (const id of productIds) result[id] = { ok: true, active: false };
      return res.json(result);
    }

    const assignmentLive = isPriceGuardRuleLive(
      assignment.assignment_starts_at,
      assignment.assignment_ends_at,
      assignment.assignment_enabled
    );
    const tierLive = isPriceGuardRuleLive(
      assignment.tier_starts_at,
      assignment.tier_ends_at,
      assignment.tier_enabled
    );

    if (!assignmentLive || !tierLive) {
      const result = {};
      for (const id of productIds) result[id] = { ok: true, active: false, tier_name: assignment.tier_name };
      return res.json(result);
    }

    const resolvedEmail = assignment.customer_email || customerEmail || '';
    const skuPricesRes = await pool.query(
      `SELECT product_id, fixed_price FROM customer_product_prices
       WHERE shop_id = $1 AND LOWER(customer_email) = LOWER($2) AND product_id = ANY($3)
         AND is_enabled = true
         AND (starts_at IS NULL OR starts_at <= NOW())
         AND (ends_at IS NULL OR ends_at >= NOW())`,
      [shop.id, resolvedEmail, productIds]
    );
    const skuPriceMap = {};
    for (const row of skuPricesRes.rows) skuPriceMap[String(row.product_id)] = Number(row.fixed_price);

    // Single GraphQL query using per-product aliases (p{id} — must start with a letter)
    const aliasFields = productIds.map((id) => `
      p${id}: product(id: "gid://shopify/Product/${id}") {
        id
        priceRangeV2 {
          minVariantPrice { amount currencyCode }
        }
        variants(first: 1) {
          nodes { price compareAtPrice }
        }
      }`).join("\n");

    const gqlData = await priceGuardShopifyAdminGraphQL(
      shop.shop_domain,
      shop.access_token,
      `#graphql\nquery BulkProductPricing {\n${aliasFields}\n}`,
      {}
    );

    const result = {};
    for (const id of productIds) {
      const product = gqlData[`p${id}`];
      if (!product) {
        result[id] = { ok: false, error: "Product not found" };
        continue;
      }
      const firstVariant = product.variants?.nodes?.[0] || null;
      const basePrice = Number(firstVariant?.price || product.priceRangeV2?.minVariantPrice?.amount || 0);
      const currencyCode = product.priceRangeV2?.minVariantPrice?.currencyCode || "GBP";
      const finalPrice = skuPriceMap[id] !== undefined
        ? skuPriceMap[id]
        : calculatePriceGuardDisplayPrice(basePrice, assignment.discount_type, assignment.discount_value);
      result[id] = {
        ok: true,
        active: true,
        base_price: basePrice,
        final_price: finalPrice,
        tier_name: assignment.tier_name,
        currency_code: currencyCode
      };
    }

    return res.json(result);
  } catch (err) {
    console.error("[PRICEGUARD_PROXY_PRICES] failed", err);
    return res.status(500).json({ ok: false, error: "Bulk price resolution failed" });
  }
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT NOW()");
    res.json({
      status: "ok",
      ok: true,
      version: APP_VERSION,
      timestamp: new Date().toISOString(),
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

    oauthStates.set(shop, { state, expiresAt: Date.now() + 600000 });

    res.setHeader(
      "Set-Cookie",
      `pg_oauth_state=${encodeURIComponent(makeSignedCookie(state))}; HttpOnly; Secure; SameSite=None; Max-Age=600; Path=/`
    );
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
    const receivedState = String(req.query.state || "");

    if (!shop || !code) {
      return res.status(400).send("Missing shop or code.");
    }

    if (!verifyHmac(req.query)) {
      return res.status(400).send("Invalid HMAC.");
    }

    let storedState = null;
    const mapEntry = oauthStates.get(shop);
    if (mapEntry && mapEntry.expiresAt > Date.now()) {
      storedState = mapEntry.state;
      oauthStates.delete(shop);
    } else {
      oauthStates.delete(shop);
      const rawStateCookie = getCookieValue(req, "pg_oauth_state");
      storedState = readSignedCookie(rawStateCookie);
    }

    if (!storedState || !receivedState || storedState !== receivedState) {
      return res.status(400).send("OAuth state mismatch. Please try installing again.");
    }

    const tokenResponse = await exchangeCodeForToken({ shop, code });
    const accessToken = tokenResponse.access_token;
    const refreshToken = tokenResponse.refresh_token;
    const expiresIn = tokenResponse.expires_in;

    if (!accessToken) {
      return res.status(500).send("No access token returned by Shopify.");
    }

    const shopRow = await ensureShopAndSettings({
      shopDomain: shop,
      accessToken,
      refreshToken,
      expiresIn
    });

    if (['growth', 'pro'].includes(shopRow.plan_name)) {
      let confirmationUrl = null;
      try {
        const activeSub = await getActiveSubscription(shop, accessToken);
        if (!activeSub) {
          const appUrl = process.env.APP_URL || "https://priceguard.sample-guard.com";
          const returnUrl = `${appUrl}/billing/callback?shop=${encodeURIComponent(shop)}`;
          confirmationUrl = await createShopifySubscription(shop, accessToken, returnUrl, shopRow.plan_name);
        }
      } catch (billingErr) {
        console.error("[BILLING] subscription check/create failed:", billingErr.message);
      }

      if (confirmationUrl) {
        res.setHeader("Set-Cookie", "pg_oauth_state=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/");
        return res.redirect(confirmationUrl);
      }
    }

    const sessionKey = await createAppSession(shopRow.id, shop);
    const sessionCookieVal = encodeURIComponent(makeSignedCookie(sessionKey));
    res.setHeader("Set-Cookie", [
      "pg_oauth_state=; HttpOnly; Secure; SameSite=None; Max-Age=0; Path=/",
      `pg_session=${sessionCookieVal}; HttpOnly; Secure; SameSite=None; Max-Age=86400; Path=/`
    ]);
    return res.redirect(getEmbeddedAppUrl(shop, host, "/"));
  } catch (e) {
    return res.status(500).send(`Auth callback failed: ${escapeHtml(e.message)}`);
  }
});

app.post('/dashboard/mark-reviewed', requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || '');
    if (!shop) return res.status(400).send('Missing or invalid shop.');
    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send('Shop not found.');

    await pool.query(
      `UPDATE settings SET reviewed_at = NOW(), updated_at = NOW() WHERE shop_id = $1`,
      [shopRow.id]
    );

    const counts = await pool.query(
      `SELECT
        (SELECT COUNT(*)::int FROM pricing_tiers WHERE shop_id = $1) AS tiers,
        (SELECT COUNT(*)::int FROM customer_assignments WHERE shop_id = $1) AS assignments,
        (SELECT COUNT(*)::int FROM customer_product_prices WHERE shop_id = $1) AS overrides`,
      [shopRow.id]
    );
    const c = counts.rows[0];
    if (c.tiers > 0 && c.assignments > 0) {
      await pool.query(
        `UPDATE settings SET onboarding_complete = true, updated_at = NOW() WHERE shop_id = $1`,
        [shopRow.id]
      );
    }

    await writeAudit(shopRow.id, 'dashboard_reviewed', 'settings', shopRow.id, {});
    return res.redirect(getEmbeddedAppUrl(shop, host, '/'));
  } catch (e) {
    return res.status(500).send(`Mark reviewed failed: ${escapeHtml(e.message)}`);
  }
});

app.get("/billing/callback", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    if (!shop) return res.status(400).send("Invalid shop parameter.");

    if (!verifyHmac(req.query)) {
      return res.status(400).send("Invalid HMAC.");
    }

    const shopRes = await pool.query(
      `SELECT id, access_token FROM shops WHERE shop_domain = $1 LIMIT 1`,
      [shop]
    );

    if (shopRes.rowCount === 0 || !shopRes.rows[0].access_token) {
      return res.status(404).send("Shop not found or not installed.");
    }

    const shopRow = shopRes.rows[0];

    const activeSub = await getActiveSubscription(shop, shopRow.access_token).catch(() => null);

    if (activeSub) {
      const subName = activeSub.name || '';
      const newPlan = subName.includes('Growth') ? 'growth' : 'pro';
      await pool.query(
        `UPDATE shops SET plan_name = $1, plan_status = 'active', updated_at = NOW()
         WHERE id = $2`,
        [newPlan, shopRow.id]
      );
    }

    const sessionKey = await createAppSession(shopRow.id, shop);
    const sessionCookieVal = encodeURIComponent(makeSignedCookie(sessionKey));
    res.setHeader(
      "Set-Cookie",
      `pg_session=${sessionCookieVal}; HttpOnly; Secure; SameSite=None; Max-Age=86400; Path=/`
    );
    return res.redirect(getEmbeddedAppUrl(shop, host, "/"));
  } catch (e) {
    return res.status(500).send(`Billing callback failed: ${escapeHtml(e.message)}`);
  }
});

app.get("/billing/upgrade", requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    if (!shop) return res.status(400).send("Missing or invalid shop.");
    const planName = ['growth', 'pro'].includes(req.query.plan) ? req.query.plan : 'pro';

    const shopRes = await pool.query(
      `SELECT id, access_token, token_expires_at FROM shops WHERE shop_domain = $1 LIMIT 1`,
      [shop]
    );

    if (shopRes.rowCount === 0 || !shopRes.rows[0].access_token) {
      return res.status(404).send("Shop not found.");
    }

    const shopRow = shopRes.rows[0];
    let accessToken = shopRow.access_token;
    if (shopRow.token_expires_at) {
      const expiresAt = new Date(shopRow.token_expires_at);
      if (expiresAt <= new Date(Date.now() + 5 * 60 * 1000)) {
        accessToken = await refreshShopToken(shop);
      }
    }

    const appUrl = process.env.APP_URL || "https://priceguard.sample-guard.com";
    const returnUrl = `${appUrl}/billing/callback?shop=${encodeURIComponent(shop)}`;
    const confirmationUrl = await createShopifySubscription(shop, accessToken, returnUrl, planName);

    if (!confirmationUrl) {
      return res.status(500).send("Failed to create subscription. Please try again.");
    }

    return res.redirect(confirmationUrl);
  } catch (e) {
    return res.status(500).send(`Billing upgrade failed: ${escapeHtml(e.message)}`);
  }
});

app.get("/app", requireShopSession, async (req, res) => {
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

app.get("/settings", requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    if (!shop) return res.status(400).send("Missing or invalid shop.");

    const dashboard = await getDashboardData(shop);
    if (!dashboard) return res.status(404).send("Shop not found.");

    const planName = escapeHtml(dashboard.shop.plan_name || "free");
    const planStatus = escapeHtml(dashboard.shop.plan_status || "inactive");
    const installedAt = dashboard.shop.installed_at
      ? new Date(dashboard.shop.installed_at).toLocaleDateString("en-GB")
      : "—";

    const content = `
      ${renderBrandHero({
        shop,
        host,
        planName: dashboard.shop.plan_name || "free",
        statusText: "Settings",
        title: "Settings",
        subtitle: "Manage your PriceGuard subscription and support options.",
        active: "settings"
      })}

      <div class="grid">
        <div class="stack">
          <div class="card">
            <h2>Subscription</h2>
            <div class="list">
              <div class="list-row"><div class="muted">Current plan</div><div><strong>${planName}</strong></div></div>
              <div class="list-row"><div class="muted">Status</div><div>${planStatus}</div></div>
              ${dashboard.shop.plan_name === 'free' ? `
              <div class="list-row"><div class="muted">Tier limit</div><div>1 tier</div></div>
              <div class="list-row"><div class="muted">Customer limit</div><div>1 customer</div></div>` : ''}
              ${dashboard.shop.plan_name === 'growth' ? `
              <div class="list-row"><div class="muted">Tier limit</div><div>3 tiers</div></div>
              <div class="list-row"><div class="muted">Customer limit</div><div>20 customers</div></div>
              <div class="list-row"><div class="muted">SKU overrides</div><div>Yes</div></div>` : ''}
              ${dashboard.shop.plan_name === 'pro' ? `
              <div class="list-row"><div class="muted">Tier limit</div><div>Unlimited</div></div>
              <div class="list-row"><div class="muted">Customer limit</div><div>Unlimited</div></div>
              <div class="list-row"><div class="muted">SKU overrides</div><div>Yes</div></div>
              <div class="list-row"><div class="muted">CSV import</div><div>Yes</div></div>
              <div class="list-row"><div class="muted">Scheduled pricing</div><div>Yes</div></div>` : ''}
            </div>
            <div class="actions" style="margin-top:16px;">
              ${dashboard.shop.plan_name === 'free' ? `
              <a class="btn primary" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=growth">Growth — $9/mo</a>
              <a class="btn" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro">Pro — $19/mo</a>` : ''}
              ${dashboard.shop.plan_name === 'growth' ? `
              <a class="btn primary" href="${getEmbeddedAppUrl(shop, host, '/billing/upgrade')}&plan=pro">Upgrade to Pro — $19/mo</a>` : ''}
              ${dashboard.shop.plan_name === 'pro' ? `
              <span class="muted" style="font-size:13px;">You're on the Pro plan. To cancel or downgrade, manage your subscription in <a href="https://accounts.shopify.com" target="_blank" style="color:#0b1f55;">Shopify billing</a>.</span>` : ''}
            </div>
          </div>

          <div class="card">
            <h2>Support</h2>
            <div class="list">
              <div class="list-row">
                <div class="muted">Email</div>
                <div><a href="mailto:support@sample-guard.com" style="color:#0b1f55;">support@sample-guard.com</a></div>
              </div>
              <div class="list-row">
                <div class="muted">Privacy policy</div>
                <div><a href="/privacy" target="_blank" style="color:#0b1f55;">View policy</a></div>
              </div>
              <div class="list-row">
                <div class="muted">Terms of service</div>
                <div><a href="/terms" target="_blank" style="color:#0b1f55;">View terms</a></div>
              </div>
            </div>
          </div>
        </div>

        <div class="stack">
          <div class="card">
            <h2>App info</h2>
            <div class="list">
              <div class="list-row"><div class="muted">App</div><div>PriceGuard</div></div>
              <div class="list-row"><div class="muted">Shop</div><div>${escapeHtml(shop)}</div></div>
              <div class="list-row"><div class="muted">Installed</div><div>${escapeHtml(installedAt)}</div></div>
              <div class="list-row"><div class="muted">Pricing tiers</div><div>${dashboard.counts.tiers}</div></div>
              <div class="list-row"><div class="muted">Customer assignments</div><div>${dashboard.counts.assignments}</div></div>
            </div>
          </div>
        </div>
      </div>

      <div class="stack" style="margin-top:18px;">
        <div class="card" style="border-color:#fecaca !important;">
          <h2 style="color:#991b1b;">Danger zone</h2>
          <div class="muted" style="margin-bottom:14px;">This will permanently delete all pricing tiers, customer assignments, and price overrides for this shop. The shop record and settings are kept. This cannot be undone.</div>
          <form method="post" action="/settings/reset?shop=${encodeURIComponent(shop)}${host ? '&host=' + encodeURIComponent(host) : ''}" onsubmit="return document.getElementById('reset-confirm').value === 'RESET';">
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
              <input id="reset-confirm" placeholder='Type RESET to confirm' style="flex:1;padding:10px 14px;border:1px solid #fecaca;border-radius:12px;font-size:14px;" oninput="document.getElementById('reset-btn').disabled=this.value!=='RESET';" />
              <button id="reset-btn" class="btn danger" type="submit" disabled>Reset all data</button>
            </div>
          </form>
        </div>
      </div>
    `;

    return res.send(renderLayout({
      shop,
      host,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      title: "PriceGuard | Settings",
      content
    }));
  } catch (e) {
    return res.status(500).send(`Settings load failed: ${escapeHtml(e.message)}`);
  }
});

app.post('/settings/reset', requireShopSession, async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || '');
    if (!shop) return res.status(400).send('Missing or invalid shop.');
    const shopRow = await getShopByDomain(shop);
    if (!shopRow) return res.status(404).send('Shop not found.');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM customer_product_prices WHERE shop_id = $1', [shopRow.id]);
      await client.query('DELETE FROM customer_assignments WHERE shop_id = $1', [shopRow.id]);
      await client.query('DELETE FROM pricing_tiers WHERE shop_id = $1', [shopRow.id]);
      await client.query(
        `UPDATE settings SET onboarding_complete = false, reviewed_at = NULL, updated_at = NOW() WHERE shop_id = $1`,
        [shopRow.id]
      );
      await client.query('COMMIT');
    } catch (e2) {
      await client.query('ROLLBACK');
      throw e2;
    } finally {
      client.release();
    }

    await writeAudit(shopRow.id, 'settings_reset', 'shop', shopRow.id, { shop_domain: shop });
    return res.redirect(getEmbeddedAppUrl(shop, host, '/'));
  } catch (e) {
    return res.status(500).send(`Reset failed: ${escapeHtml(e.message)}`);
  }
});

const LEGAL_PAGE_STYLE = `
<style>
body{margin:0;background:#f4f6f8;color:#111827;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;}
.wrap{max-width:860px;margin:40px auto;padding:0 20px 60px;}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:24px;padding:36px 40px;box-shadow:0 10px 30px rgba(15,23,42,.06);}
h1{margin:0 0 8px;font-size:32px;color:#0f172a;}
h2{margin:32px 0 10px;font-size:20px;color:#0f172a;border-top:1px solid #f1f5f9;padding-top:24px;}
p,li{color:#4b5563;line-height:1.7;margin:0 0 10px;}
ul{padding-left:20px;margin:0 0 10px;}
.small{color:#6b7280;font-size:14px;margin-bottom:20px;}
a{color:#0b1f55;}
.footer{margin-top:28px;padding-top:20px;border-top:1px solid #f1f5f9;font-size:13px;color:#9ca3af;display:flex;gap:16px;flex-wrap:wrap;}
</style>`;

app.get('/privacy', (req, res) => {
  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PriceGuard — Privacy Policy</title>
${LEGAL_PAGE_STYLE}
</head>
<body>
<div class="wrap">
<div class="card">
<h1>Privacy Policy</h1>
<p class="small">Last updated: 23 April 2026</p>

<p>PriceGuard ("we", "us") is a Shopify app that provides customer-specific pricing tools for merchants. This policy explains what data we collect, how we use it, and your rights under applicable data protection law including the UK GDPR and EU GDPR.</p>

<h2>Data We Collect</h2>
<ul>
<li><strong>Shop domain and OAuth access token</strong> — required to authenticate with the Shopify Admin API and operate the app.</li>
<li><strong>Customer email addresses</strong> — entered by merchants to assign customers to pricing tiers. We do not collect these from Shopify; merchants enter them manually.</li>
<li><strong>Shopify customer IDs</strong> — optionally provided by merchants alongside email addresses.</li>
<li><strong>Pricing configuration data</strong> — pricing tiers, discount values, date ranges, and SKU-level fixed prices set by merchants.</li>
<li><strong>Audit log entries</strong> — timestamped records of changes made in the app, used for support and troubleshooting.</li>
<li><strong>Session tokens</strong> — short-lived tokens (24 hours) stored server-side to maintain the embedded app session.</li>
</ul>

<h2>How We Use Data</h2>
<ul>
<li>Deliver the core app functionality: displaying trade prices to logged-in customers on your storefront.</li>
<li>Authenticate and maintain your merchant session inside the Shopify admin.</li>
<li>Respond to GDPR data access and deletion requests from Shopify.</li>
<li>Investigate support requests and diagnose technical issues.</li>
</ul>

<h2>Data Sharing</h2>
<p>We do not sell, rent, or share merchant or customer data with third parties for marketing purposes. Data may be shared only:</p>
<ul>
<li>With infrastructure providers (database hosting) under appropriate data processing agreements.</li>
<li>Where required by law or to comply with a valid legal obligation.</li>
</ul>

<h2>GDPR Compliance</h2>
<p>We support Shopify's mandatory GDPR webhooks:</p>
<ul>
<li><strong>Customer data request</strong> — we return all pricing assignments and product prices linked to the customer.</li>
<li><strong>Customer redact</strong> — we permanently delete all pricing data linked to the customer within 30 days of the request.</li>
<li><strong>Shop redact</strong> — we permanently delete all shop data within 30 days of app uninstallation.</li>
</ul>
<p>The lawful basis for processing merchant data is the performance of a contract (providing the app service). Customer email addresses are processed on behalf of merchants under their own lawful basis as data controllers.</p>

<h2>Data Retention</h2>
<p>Merchant data is retained for as long as the app is installed. Following uninstallation, data is deleted within 30 days in response to Shopify's shop/redact webhook. Session tokens expire after 24 hours and are purged automatically.</p>

<h2>Security</h2>
<p>All data is transmitted over HTTPS. Access tokens are stored encrypted at rest. Webhook payloads are verified using HMAC-SHA256 signatures. We implement session signing to prevent tampering.</p>

<h2>Your Rights</h2>
<p>Under UK/EU GDPR, you have the right to access, correct, or request deletion of personal data we hold. To exercise these rights, or to raise a data protection concern, please contact us.</p>

<h2>Contact</h2>
<p>Email: <a href="mailto:support@sample-guard.com">support@sample-guard.com</a></p>

<div class="footer">
  <a href="/terms">Terms of Service</a>
  <span>&middot;</span>
  <a href="/privacy">Privacy Policy</a>
</div>
</div>
</div>
</body>
</html>`);
});

app.get('/terms', (req, res) => {
  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PriceGuard — Terms of Service</title>
${LEGAL_PAGE_STYLE}
</head>
<body>
<div class="wrap">
<div class="card">
<h1>Terms of Service</h1>
<p class="small">Last updated: 23 April 2026</p>

<p>These Terms of Service ("Terms") govern your access to and use of the PriceGuard Shopify app ("App", "Service"). By installing or using PriceGuard you agree to these Terms.</p>

<h2>1. The Service</h2>
<p>PriceGuard is a Shopify embedded app that allows merchants to create customer-specific pricing tiers and display trade prices on their storefront. The App is provided as a subscription service through the Shopify App Store.</p>

<h2>2. Eligibility</h2>
<p>You must have a valid Shopify store and agree to Shopify's Partner Program terms to install the App. You must be at least 18 years old and have authority to enter into these Terms on behalf of your business.</p>

<h2>3. Subscription and Billing</h2>
<p>PriceGuard offers three plans:</p>
<ul>
<li><strong>Free</strong> — 1 pricing tier, 1 trade customer. No charge.</li>
<li><strong>Growth</strong> — $9/month. 3 tiers, 20 customers, SKU-level price overrides.</li>
<li><strong>Pro</strong> — $19/month. Unlimited tiers and customers, SKU overrides, CSV import, and scheduled pricing.</li>
</ul>
<p>Billing for the Growth and Pro plans is handled by Shopify through the App Store. Charges appear on your Shopify invoice. A 14-day free trial applies to new Growth and Pro subscriptions. You may cancel at any time; cancellation takes effect at the end of the current billing cycle. On cancellation or uninstallation, your account reverts to the Free plan.</p>

<h2>4. Acceptable Use</h2>
<p>You agree not to:</p>
<ul>
<li>Use the App for any unlawful purpose or in violation of Shopify's Terms of Service.</li>
<li>Attempt to reverse-engineer, decompile, or extract the source code of the App.</li>
<li>Use the App to store or transmit malicious code.</li>
<li>Resell or sublicense the App without written permission.</li>
</ul>

<h2>5. Data and Privacy</h2>
<p>Your use of the App is subject to our <a href="/privacy">Privacy Policy</a>. You are responsible for ensuring you have a lawful basis to share customer email addresses with PriceGuard as part of your own GDPR obligations.</p>

<h2>6. Intellectual Property</h2>
<p>The App and all related materials are owned by PriceGuard and protected by copyright and other intellectual property laws. These Terms do not transfer any ownership rights to you.</p>

<h2>7. Disclaimers</h2>
<p>The App is provided "as is" without warranty of any kind, express or implied. We do not warrant that the App will be error-free, uninterrupted, or meet your specific requirements. Pricing display depends on your Shopify theme and extension configuration.</p>

<h2>8. Limitation of Liability</h2>
<p>To the maximum extent permitted by law, PriceGuard shall not be liable for any indirect, incidental, special, or consequential damages arising from your use of the App, including loss of revenue or data. Our total liability shall not exceed the fees paid by you in the 3 months prior to the event giving rise to the claim.</p>

<h2>9. Termination</h2>
<p>We may suspend or terminate your access to the App at our discretion if you breach these Terms. You may terminate by uninstalling the App from your Shopify store at any time.</p>

<h2>10. Changes to Terms</h2>
<p>We may update these Terms from time to time. Continued use of the App after changes are posted constitutes acceptance of the revised Terms. Material changes will be notified via the App or email.</p>

<h2>11. Governing Law</h2>
<p>These Terms are governed by the laws of England and Wales. Any disputes shall be subject to the exclusive jurisdiction of the courts of England and Wales.</p>

<h2>12. Contact</h2>
<p>Email: <a href="mailto:support@sample-guard.com">support@sample-guard.com</a></p>

<div class="footer">
  <a href="/privacy">Privacy Policy</a>
  <span>&middot;</span>
  <a href="/terms">Terms of Service</a>
</div>
</div>
</div>
</body>
</html>`);
});

app.get('/support', (req, res) => {
  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PriceGuard — Support</title>
${LEGAL_PAGE_STYLE}
</head>
<body>
<div class="wrap">
<div class="card">
<h1>Support</h1>
<p class="small">PriceGuard — Customer pricing for Shopify</p>

<p>We're here to help. If you have a question, run into an issue, or need help getting set up, please reach out via email and we'll get back to you as soon as possible.</p>

<h2>Contact Us</h2>
<p>Email: <a href="mailto:support@sample-guard.com">support@sample-guard.com</a></p>
<p>We aim to respond to all support requests within one business day.</p>

<h2>Common Questions</h2>
<p><strong>How do I create a pricing tier?</strong><br>
Go to the Pricing Tiers page inside the app and fill in the tier name, discount type (percentage or fixed amount), and an optional date range.</p>

<p><strong>How do I assign a customer?</strong><br>
Go to Customer Assignments and enter the customer's email address. Free plan supports 1 customer; upgrade to Premium for unlimited.</p>

<p><strong>Prices aren't showing on my storefront.</strong><br>
Make sure the PriceGuard theme extension is enabled in your Shopify theme editor. Navigate to Online Store → Themes → Customize, and add the PriceGuard block to your product page template.</p>

<p><strong>How do I upgrade to Premium?</strong><br>
Click "Upgrade to Premium" on the dashboard or visit the Billing page inside the app. Premium includes unlimited tiers, customers, and SKU-level price overrides.</p>

<h2>Legal</h2>
<div class="footer">
  <a href="/privacy">Privacy Policy</a>
  <span>&middot;</span>
  <a href="/terms">Terms of Service</a>
</div>
</div>
</div>
</body>
</html>`);
});

app.listen(port, () => {
  console.log(`PriceGuard listening on ${port}`);
});
