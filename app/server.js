require("dotenv").config();
const express = require("express");
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
    throw new Error(`Shopify GraphQL request failed: ${response.status}`);
  }

  if (json.errors && json.errors.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
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
       VALUES ($1, 'system', 'system@priceflow.local', $2, 'shop', $3, $4::jsonb)`,
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

async function writeAudit(shopId, action, entityType, entityId, metadata = {}) {
  await pool.query(
    `INSERT INTO audit_logs (shop_id, actor_type, actor_email, action, entity_type, entity_id, metadata_json)
     VALUES ($1, 'system', 'system@priceflow.local', $2, $3, $4, $5::jsonb)`,
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
    </style>
  </head>
  <body>
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
  </body>
</html>
  `;
}

function renderPublicHome() {
  return `
    <html>
      <head>
        <title>PriceFlow</title>
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
          <h1>PriceFlow</h1>
          <p>Embedded app shell is ready.</p>
          <form class="row" method="get" action="/install">
            <input name="shop" placeholder="store-name.myshopify.com" />
            <button type="submit">Install app</button>
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

function renderNav(shop, host, active) {
  const dashUrl = getEmbeddedAppUrl(shop, host, "/");
  const tiersUrl = getEmbeddedAppUrl(shop, host, "/pricing-tiers");
  const assignmentsUrl = getEmbeddedAppUrl(shop, host, "/customer-assignments");
  return `
    <div class="nav">
      <a class="${active === "dashboard" ? "active" : ""}" href="${dashUrl}">Dashboard</a>
      <a class="${active === "tiers" ? "active" : ""}" href="${tiersUrl}">Pricing tiers</a>
      <a class="${active === "assignments" ? "active" : ""}" href="${assignmentsUrl}">Customer assignments</a>
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
    { label: "Install app", done: true, desc: "OAuth and token storage complete." },
    { label: "Create first pricing tier", done: dashboard.counts.tiers > 0, desc: "Set up Gold, Silver, VIP or another trade tier." },
    { label: "Assign first trade customer", done: dashboard.counts.assignments > 0, desc: "Link a customer to a pricing tier." },
    { label: "Add specific product prices", done: dashboard.counts.overrides > 0, desc: "Create customer-specific price overrides where needed." },
    { label: "Import a CSV", done: dashboard.counts.imports > 0, desc: "Bulk upload pricing and assignments." }
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
    <div class="topbar">
      <div>
        <h1>PriceFlow</h1>
        <div class="sub">
          Give every trade customer the right price automatically. Start with one trade customer on the free plan, then scale with tiers, overrides and CSV imports.
        </div>
      </div>
      <div class="shop-meta">
        <span class="pill">Shop: ${shopSafe}</span>
        <span class="pill">Plan: ${planName}</span>
        <span class="pill">Status: ${planStatus}</span>
      </div>
    </div>

    ${renderNav(shop, host, "dashboard")}

    <div class="grid">
      <div class="stack">
        <div class="card">
          <h2>Get started</h2>
          <div class="muted">
            Your embedded admin shell is live. The next goal is simple: create a first tier, assign a first trade customer, then prove the value with CSV import.
          </div>

          <div class="actions">
            <a class="btn primary" href="${tierUrl}">Create first tier</a>
            <button class="btn" onclick="alert('Next build: CSV import screen')">Import CSV</button>
            <a class="btn" href="${assignmentsUrl}">Assign customer</a>
          </div>

          <div class="mini-grid">
            <div class="stat"><div class="stat-label">Trade customers used</div><div class="stat-value">${escapeHtml(usageText)}</div></div>
            <div class="stat"><div class="stat-label">Pricing tiers</div><div class="stat-value">${dashboard.counts.tiers}</div></div>
            <div class="stat"><div class="stat-label">Price overrides</div><div class="stat-value">${dashboard.counts.overrides}</div></div>
            <div class="stat"><div class="stat-label">CSV imports</div><div class="stat-value">${dashboard.counts.imports}</div></div>
          </div>
        </div>

        <div class="card">
          <h2>Onboarding checklist</h2>
          ${checklistHtml}
        </div>
      </div>

      <div class="stack">
        <div class="card">
          <h2>Current setup</h2>
          <div class="list">
            <div class="list-row"><div class="muted">Embedded app</div><div class="success">${host ? "Ready" : "Direct preview mode"}</div></div>
            <div class="list-row"><div class="muted">Install status</div><div>${dashboard.shop.installed_at ? "Installed" : "Not installed"}</div></div>
            <div class="list-row"><div class="muted">Installed at</div><div>${escapeHtml(installedAt)}</div></div>
            <div class="list-row"><div class="muted">Onboarding complete</div><div>${onboardingDone ? "Yes" : "Not yet"}</div></div>
            <div class="list-row"><div class="muted">Pricing display mode</div><div>${escapeHtml(dashboard.settings.pricing_display_mode || "replace")}</div></div>
            <div class="list-row"><div class="muted">App enabled</div><div>${dashboard.settings.app_enabled ? "Yes" : "No"}</div></div>
          </div>
        </div>

        <div class="card">
          <h2>Free plan value</h2>
          <div class="muted">
            The free plan proves the magic with one trade customer. Paid plans will unlock more customer capacity, CSV workflows, collection pricing and customer-specific product prices.
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceFlow", content });
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
    <div class="topbar">
      <div>
        <h1>Pricing tiers</h1>
        <div class="sub">
          Create trade pricing rules with effective dates. This is the core building block for customer-specific wholesale pricing.
        </div>
      </div>
      <div class="shop-meta">
        <span class="pill">Shop: ${escapeHtml(shop)}</span>
        <span class="pill">Plan: ${escapeHtml(dashboard.shop.plan_name || "free")}</span>
        <span class="pill">Trade customers limit: ${escapeHtml(String(dashboard.settings.free_plan_customer_limit || 1))}</span>
      </div>
    </div>

    ${renderNav(shop, host, "tiers")}

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

  return renderLayout({ shop, host, apiKey, title: "PriceFlow | Pricing tiers", content });
}

function renderCustomerAssignmentsPage({ shop, host, apiKey, dashboard, tiers, assignments }) {
  const customerLimit = Number(dashboard.settings.free_plan_customer_limit || 1);

  const rows = assignments.length === 0
    ? `<div class="empty">No customer assignments yet. Assign your first trade customer to a pricing tier below.</div>`
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
    <div class="topbar">
      <div>
        <h1>Customer assignments</h1>
        <div class="sub">
          Connect trade customers to pricing tiers with optional effective dates. This is how the free plan proves value with one trade customer.
        </div>
      </div>
      <div class="shop-meta">
        <span class="pill">Shop: ${escapeHtml(shop)}</span>
        <span class="pill">Plan: ${escapeHtml(dashboard.shop.plan_name || "free")}</span>
        <span class="pill">Trade customers limit: ${escapeHtml(String(customerLimit))}</span>
      </div>
    </div>

    ${renderNav(shop, host, "assignments")}

    <div class="grid">
      <div class="stack">
        ${rows}
      </div>

      <div class="stack">
        <div class="card">
          <h2>Assign customer to tier</h2>
          <div class="actions" style="margin-bottom:12px;">
            <button type="button" class="btn" onclick="window.location.href='${getEmbeddedAppUrl(shop, host, "/customer-search")}';">Search Shopify customers</button>
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
            <div class="list-row"><div>One row per customer</div><div class="muted">Manual MVP</div></div>
            <div class="list-row"><div>Email is primary</div><div class="muted">Simple to test</div></div>
            <div class="list-row"><div>Optional dates</div><div class="muted">Campaign ready</div></div>
            <div class="list-row"><div>Free plan</div><div class="muted">1 trade customer</div></div>
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceFlow | Customer assignments", content });
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
    return res.status(500).send(`Pricing tiers load failed: ${escapeHtml(e.message)}`);
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


app.get("/api/customer-search", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const q = String(req.query.q || "").trim();

    if (!shop) {
      return res.status(400).json({ ok: false, error: "Missing or invalid shop." });
    }

    if (!q) {
      return res.json({ ok: true, customers: [] });
    }

    const customers = await searchShopifyCustomers(shop, q);
    return res.json({ ok: true, customers });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/customer-search", async (req, res) => {
  try {
    const shop = sanitizeShop(req.query.shop);
    const host = String(req.query.host || "");
    const q = String(req.query.q || "").trim();

    if (!shop) {
      return res.status(400).send("Missing or invalid shop.");
    }

    let customers = [];
    let error = "";

    if (q) {
      try {
        customers = await searchShopifyCustomers(shop, q);
      } catch (err) {
        error = err.message;
      }
    }

    return res.send(renderCustomerSearchPage({
      shop,
      host,
      apiKey: process.env.SHOPIFY_API_KEY || "",
      query: q,
      customers,
      error
    }));
  } catch (e) {
    return res.status(500).send(`Customer search load failed: ${escapeHtml(e.message)}`);
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
    return res.status(500).send(`Customer assignments load failed: ${escapeHtml(e.message)}`);
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


function renderCustomerSearchPage({ shop, host, apiKey, query = "", customers = [], error = "" }) {
  const searchValue = escapeHtml(query || "");
  const resultsHtml = error
    ? `<div class="empty">Search failed: ${escapeHtml(error)}</div>`
    : customers.length === 0 && query
      ? `<div class="empty">No Shopify customers found for that search.</div>`
      : customers.map((customer) => {
          const subtitle = [customer.email || "", customer.phone || ""].filter(Boolean).join(" · ");
          const tags = Array.isArray(customer.tags) && customer.tags.length ? customer.tags.join(", ") : "No tags";
          const backUrl =
            getEmbeddedAppUrl(shop, host, "/customer-assignments") +
            "&use_email=" + encodeURIComponent(customer.email || "") +
            "&use_id=" + encodeURIComponent(customer.short_id || "");
          return `
            <div class="card" style="padding:14px;">
              <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start;">
                <div>
                  <div style="font-weight:700;">${escapeHtml(customer.display_name)}</div>
                  <div class="muted" style="margin-top:4px;">${escapeHtml(subtitle || "No email/phone available")}</div>
                  <div class="muted" style="margin-top:4px;">Shopify ID: ${escapeHtml(customer.short_id || "")}</div>
                  <div class="muted" style="margin-top:4px;">Tags: ${escapeHtml(tags)}</div>
                </div>
                <div>
                  <a class="btn small" href="${backUrl}">Use customer</a>
                </div>
              </div>
            </div>
          `;
        }).join("");

  const content = `
    <div class="topbar">
      <div>
        <h1>Search Shopify customers</h1>
        <div class="sub">
          Find an existing Shopify customer, then send their email and Shopify customer ID back into the assignment form.
        </div>
      </div>
      <div class="shop-meta">
        <span class="pill">Shop: ${escapeHtml(shop)}</span>
      </div>
    </div>

    ${renderNav(shop, host, "assignments")}

    <div class="grid">
      <div class="stack">
        <div class="card">
          <h2>Customer search</h2>
          <form method="get" action="/customer-search">
            <input type="hidden" name="shop" value="${escapeHtml(shop)}" />
            ${host ? `<input type="hidden" name="host" value="${escapeHtml(host)}" />` : ""}
            <div class="form-grid">
              <div class="field full">
                <label for="q">Search by email or name</label>
                <input id="q" name="q" value="${searchValue}" placeholder="e.g. buyer@example.com or Dan Waddell" />
              </div>
            </div>
            <div class="actions">
              <button class="btn primary" type="submit">Search customers</button>
              <button type="button" class="btn" onclick="window.location.href='${getEmbeddedAppUrl(shop, host, "/customer-assignments")}';">Back to assignments</button>
            </div>
          </form>
        </div>

        ${resultsHtml ? `<div class="stack">${resultsHtml}</div>` : ""}
      </div>

      <div class="stack">
        <div class="card">
          <h2>How it works</h2>
          <div class="list">
            <div class="list-row"><div>Search Shopify</div><div class="muted">Live customer lookup</div></div>
            <div class="list-row"><div>Use customer</div><div class="muted">Prefills assignment form</div></div>
            <div class="list-row"><div>Email + ID</div><div class="muted">Stored with assignment</div></div>
          </div>
        </div>
      </div>
    </div>
  `;

  return renderLayout({ shop, host, apiKey, title: "PriceFlow | Search Shopify customers", content });
}

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
    return res.status(500).send(`Embedded app load failed: ${escapeHtml(e.message)}`);
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

app.listen(port, () => {
  console.log(`PriceFlow listening on ${port}`);
});
