(function () {
  if (!window.PriceGuard || !window.PriceGuard.customerLoggedIn) return;

  const PG = window.PriceGuard;

  function log(...args) {
    if (PG.debug) console.log("[PriceGuard Sitewide]", ...args);
  }

  function formatMoney(amount, currencyCode) {
    try {
      return new Intl.NumberFormat(undefined, {
        style: "currency",
        currency: currencyCode || "GBP"
      }).format(Number(amount || 0));
    } catch {
      return `${currencyCode || "GBP"} ${Number(amount || 0).toFixed(2)}`;
    }
  }

  function normalizeText(str) {
    return String(str || "").replace(/\s+/g, " ").trim();
  }

  function isLikelyMoneyText(text) {
    const t = normalizeText(text);
    return /[$£€]\s?\d/.test(t) || /\d[\d,.]*\s?(GBP|USD|EUR)/i.test(t);
  }

  // Collect every numeric product ID visible on the page from multiple sources.
  function collectPageProductIds() {
    const ids = new Set();

    // 1. Explicit data-product-id attributes — covers product cards, forms, and most theme elements
    document.querySelectorAll("[data-product-id]").forEach((el) => {
      const id = String(el.dataset.productId || "").trim();
      if (/^\d+$/.test(id)) ids.add(id);
    });

    // 2. ShopifyAnalytics — set on product and collection pages
    try {
      const meta = window.ShopifyAnalytics && window.ShopifyAnalytics.meta;
      if (meta && meta.product && meta.product.id) ids.add(String(meta.product.id));
    } catch {}

    // 3. JSON-LD product schema — Shopify stores product ID in productID field
    document.querySelectorAll('script[type="application/ld+json"]').forEach((el) => {
      try {
        const parsed = JSON.parse(el.textContent || "{}");
        const items = Array.isArray(parsed) ? parsed : [parsed];
        for (const item of items) {
          if (item["@type"] === "Product" && item.productID) ids.add(String(item.productID));
        }
      } catch {}
    });

    // 4. data-product attribute — some themes embed the product object as JSON or a bare ID
    document.querySelectorAll("[data-product]").forEach((el) => {
      try {
        const val = String(el.dataset.product || "").trim();
        if (/^\d+$/.test(val)) {
          ids.add(val);
        } else {
          const parsed = JSON.parse(val);
          if (parsed && parsed.id) ids.add(String(parsed.id));
        }
      } catch {}
    });

    // 5. Inline application/json product blobs (section JSON rendering)
    document.querySelectorAll('script[type="application/json"]').forEach((el) => {
      try {
        const parsed = JSON.parse(el.textContent || "{}");
        if (parsed && parsed.id && (parsed.variants || parsed.title || parsed.handle)) {
          ids.add(String(parsed.id));
        }
      } catch {}
    });

    // 6. .product-card and generic card containers with a data-product-id descendant
    document.querySelectorAll(".product-card, .card--product, [data-product-card]").forEach((el) => {
      const id = String(el.dataset.productId || el.dataset.productid || "").trim();
      if (/^\d+$/.test(id)) ids.add(id);
    });

    // 7. Dawn-style element IDs — e.g. id="CardLink-template--123__product-grid-10540990824758"
    //    The product ID is the numeric suffix after the last hyphen.
    document.querySelectorAll('[id*="__product-grid-"], [id*="__featured_collection-"]').forEach((el) => {
      const match = /-(\d+)$/.exec(el.id);
      if (match) ids.add(match[1]);
    });

    return Array.from(ids)
      .filter((id) => /^\d+$/.test(id))
      .slice(0, 50);
  }

  // Price selector priority — most specific first.
  const PRICE_SELECTORS = [
    ".price-item--regular",
    ".price-item",
    ".price__regular .price-item",
    ".price",
    ".product-price",
    "[data-price]"
  ];

  // Find the best single price node within a product container.
  function bestPriceNodeIn(container) {
    for (const sel of PRICE_SELECTORS) {
      const candidates = Array.from(container.querySelectorAll(sel)).filter((n) =>
        isLikelyMoneyText(normalizeText(n.textContent))
      );
      if (candidates.length) return candidates[0];
    }
    return null;
  }

  // Return one price node per DOM container anchored to productId.
  function findPriceNodesForProduct(productId) {
    const nodes = [];
    const seen = new Set();

    function addBestIn(container) {
      const node = bestPriceNodeIn(container);
      if (node && !seen.has(node)) {
        seen.add(node);
        nodes.push(node);
      }
    }

    // Strategy A: explicit data-product-id containers (most themes)
    document.querySelectorAll(`[data-product-id="${productId}"]`).forEach(addBestIn);

    // Strategy B: Dawn-style __product-grid- element IDs — walk up to the card wrapper
    document.querySelectorAll('[id*="__product-grid-"], [id*="__featured_collection-"]').forEach((el) => {
      const match = /-(\d+)$/.exec(el.id);
      if (!match || match[1] !== productId) return;
      const cardWrapper = el.closest(".card-wrapper, .product-card-wrapper");
      if (cardWrapper) addBestIn(cardWrapper);
    });

    return nodes;
  }

  // Apply the PriceGuard display to a single price node.
  // Uses the same CSS classes as priceguard-pricing.js so existing CSS applies.
  function applyPriceToNode(node, data) {
    if (!data || !data.ok || !data.active) return;

    const signature = `${data.product_id}:${data.final_price}:${data.tier_name}`;

    // Idempotency — skip if this exact price is already applied
    const existingWrap = node.closest("[data-priceguard-applied]");
    if (existingWrap && existingWrap.dataset.priceguardApplied === signature) return;

    const finalText = formatMoney(data.final_price, data.currency_code);

    let wrap = node.closest(".priceguard-price-wrap");
    if (!wrap) {
      wrap = document.createElement("span");
      wrap.className = "priceguard-price-wrap";
      node.parentNode.insertBefore(wrap, node);
      wrap.appendChild(node);
    }
    wrap.dataset.priceguardApplied = signature;

    if (data.base_price !== data.final_price) {
      node.classList.add("priceguard-original-price");
    } else {
      node.classList.remove("priceguard-original-price");
    }

    let customEl = wrap.querySelector(".priceguard-final-price");
    if (!customEl) {
      customEl = document.createElement("span");
      customEl.className = "priceguard-final-price";
      node.insertAdjacentElement("afterend", customEl);
    }
    customEl.textContent = finalText;

    let badgeEl = wrap.querySelector(".priceguard-tier-badge");
    if (!badgeEl) {
      badgeEl = document.createElement("span");
      badgeEl.className = "priceguard-tier-badge";
      customEl.insertAdjacentElement("afterend", badgeEl);
    }
    badgeEl.textContent = `${data.tier_name} price`;
  }

  async function run() {
    try {
      const productIds = collectPageProductIds();
      if (!productIds.length) {
        log("No product IDs found on page");
        return;
      }

      log("Found product IDs:", productIds);

      const tags = Array.isArray(PG.customerTags) ? PG.customerTags.join(",") : "";
      const email = PG.customerEmail || "";
      const url =
        `${PG.proxySitewideBase}` +
        `?product_ids=${encodeURIComponent(productIds.join(","))}` +
        `&logged_in_customer_id=${encodeURIComponent(PG.customerId || "")}` +
        `&customer_email=${encodeURIComponent(email)}` +
        `&customer_tags=${encodeURIComponent(tags)}`;

      const res = await fetch(url, {
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      });

      if (!res.ok) {
        log("Bulk price fetch failed:", res.status);
        return;
      }

      const priceMap = await res.json();
      log("Bulk price response:", priceMap);

      // Top-level ok:false means early exit (not logged in, etc.)
      if (!priceMap || priceMap.ok === false) return;

      for (const [productId, data] of Object.entries(priceMap)) {
        if (!data || !data.active) continue;
        const priceNodes = findPriceNodesForProduct(productId);
        log(`Product ${productId}: ${priceNodes.length} price node(s) found`);
        for (const node of priceNodes) {
          applyPriceToNode(node, { ...data, product_id: productId });
        }
      }
    } catch (_) {
      // Never break the storefront
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run);
  } else {
    run();
  }
})();
