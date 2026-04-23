(function () {
  if (!window.PriceGuard || !window.PriceGuard.customerLoggedIn) return;

  const PG = window.PriceGuard;
  const proxyBase = PG.proxyBase;
  let inFlight = false;
  let priceObserver = null;

  function log(...args) {
    if (PG.debug) console.log("[PriceGuard]", ...args);
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

  function getProductId() {
    if (PG.productId) return String(PG.productId);

    if (window.meta && window.meta.product && window.meta.product.id) {
      return String(window.meta.product.id);
    }

    const productJsonCandidates = [
      document.querySelector('script[type="application/json"][data-product-json]'),
      ...Array.from(document.querySelectorAll('script[type="application/json"]'))
    ].filter(Boolean);

    for (const node of productJsonCandidates) {
      try {
        const parsed = JSON.parse(node.textContent || "{}");
        if (parsed && parsed.id && (parsed.variants || parsed.title || parsed.handle)) {
          return String(parsed.id);
        }
      } catch {}
    }

    const formSelectors = [
      'form[action*="/cart/add"][data-productid]',
      'product-form form[data-productid]',
      'form[action*="/cart/add"]'
    ];

    for (const sel of formSelectors) {
      const form = document.querySelector(sel);
      if (!form) continue;
      if (form.dataset.productid) return String(form.dataset.productid);
      if (form.dataset.productId) return String(form.dataset.productId);
    }

    const input = document.querySelector('input[name="product-id"], input[data-product-id]');
    if (input) return String(input.value || input.dataset.productId || "");

    return null;
  }

  function findPriceCandidates() {
    const selectors = [
      '.product .price__current',
      '.product .price-item--regular',
      '.product .price__regular .price-item',
      '.product .price .price-item',
      '.product__info-container .price-item',
      '.product__info-container .price',
      '.product__info-wrapper .price',
      '.product__info-wrapper .price-item',
      '.product-form__buttons ~ .price',
      '.product-form__submit ~ .price',
      'price-per-item .price-item',
      '.price-item',
      '.price'
    ];

    const nodes = [];
    for (const sel of selectors) {
      document.querySelectorAll(sel).forEach((node) => {
        if (!node) return;
        if (!document.body.contains(node)) return;
        const text = normalizeText(node.textContent);
        if (!isLikelyMoneyText(text)) return;
        nodes.push(node);
      });
    }

    const unique = Array.from(new Set(nodes));

    unique.sort((a, b) => {
      const aRect = a.getBoundingClientRect();
      const bRect = b.getBoundingClientRect();
      const aScore = aRect.top + aRect.left;
      const bScore = bRect.top + bRect.left;
      return aScore - bScore;
    });

    return unique;
  }

  function chooseMainPriceNode() {
    const candidates = findPriceCandidates();
    if (!candidates.length) return null;

    const strong = candidates.find((node) =>
      node.closest('.product__info-container, .product__info-wrapper, main, product-info')
    );

    return strong || candidates[0];
  }

  // Watch the wrapper's parent. If the theme tears out our wrapper or removes
  // our injected price element, re-apply immediately using the cached data.
  function observePriceNode(wrap, data) {
    if (priceObserver) priceObserver.disconnect();
    const parent = wrap.parentNode;
    if (!parent) return;

    priceObserver = new MutationObserver(() => {
      const wrapGone = !parent.contains(wrap);
      const priceElGone = !wrap.querySelector(".priceguard-final-price");
      if (wrapGone || priceElGone) {
        priceObserver.disconnect();
        priceObserver = null;
        setTimeout(() => applyResolvedPrice(data), 50);
      }
    });

    priceObserver.observe(parent, { childList: true, subtree: true });
  }

  function applyResolvedPrice(data) {
    if (!data || !data.ok || !data.active) {
      log("No active resolved price to apply", data);
      return;
    }

    const node = chooseMainPriceNode();
    if (!node) {
      log("Could not find a product price node");
      return;
    }

    const signature = `${data.product_id}:${data.final_price}:${data.tier_name}`;

    // Idempotency: if our wrapper already carries this exact signature, nothing to do.
    const existingWrap = node.closest("[data-priceguard-applied]");
    if (existingWrap && existingWrap.dataset.priceguardApplied === signature) {
      log("Price already applied (idempotent)");
      return;
    }

    const finalText = formatMoney(data.final_price, data.currency_code);

    log("Applying price", {
      productId: data.product_id,
      base: data.base_price,
      final: data.final_price,
      tier: data.tier_name,
      nodeTextBefore: normalizeText(node.textContent)
    });

    // Build or reuse wrapper — a single span that contains the original node
    // plus our injected elements. We never modify the original node's text so
    // the theme can keep writing to it without stomping our display.
    let wrap = node.closest(".priceguard-price-wrap");
    if (!wrap) {
      wrap = document.createElement("span");
      wrap.className = "priceguard-price-wrap";
      node.parentNode.insertBefore(wrap, node);
      wrap.appendChild(node);
    }
    wrap.dataset.priceguardApplied = signature;

    // Style the original element as struck-through when prices differ.
    // No textContent mutation — the theme owns that node.
    if (data.base_price !== data.final_price) {
      node.classList.add("priceguard-original-price");
    } else {
      node.classList.remove("priceguard-original-price");
    }

    // Inject or update the custom price element (sibling to the original node).
    let customEl = wrap.querySelector(".priceguard-final-price");
    if (!customEl) {
      customEl = document.createElement("span");
      customEl.className = "priceguard-final-price";
      node.insertAdjacentElement("afterend", customEl);
    }
    customEl.textContent = finalText;

    // Inject or update the tier badge.
    let badgeEl = wrap.querySelector(".priceguard-tier-badge");
    if (!badgeEl) {
      badgeEl = document.createElement("span");
      badgeEl.className = "priceguard-tier-badge";
      customEl.insertAdjacentElement("afterend", badgeEl);
    }
    badgeEl.textContent = `${data.tier_name} price`;

    observePriceNode(wrap, data);
  }

  async function fetchResolvedPrice(productId) {
    const tags = Array.isArray(PG.customerTags) ? PG.customerTags.join(",") : "";
    const email = PG.customerEmail || "";
    const url = `${proxyBase}?product_id=${encodeURIComponent(productId)}&logged_in_customer_id=${encodeURIComponent(PG.customerId || "")}&customer_email=${encodeURIComponent(email)}&customer_tags=${encodeURIComponent(tags)}`;
    const res = await fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });

    if (!res.ok) {
      throw new Error(`Proxy failed with ${res.status}`);
    }

    const json = await res.json();
    log("Proxy response", json);
    return json;
  }

  async function refreshPrice(reason) {
    if (inFlight) return;
    const productId = getProductId();
    if (!productId) {
      log("No product id found");
      return;
    }

    inFlight = true;
    try {
      log("Refreshing price because:", reason, "productId:", productId);
      const data = await fetchResolvedPrice(productId);
      log("Resolved storefront pricing payload", data);
      applyResolvedPrice(data);
    } catch (err) {
      console.warn("[PriceGuard] pricing refresh failed", err);
    } finally {
      inFlight = false;
    }
  }

  function wireVariantListeners() {
    document.addEventListener("change", (event) => {
      const t = event.target;
      if (!t) return;

      if (
        t.matches('select[name="id"]') ||
        t.matches('input[name="id"]') ||
        t.matches('variant-selects select') ||
        t.matches('fieldset input[type="radio"]') ||
        t.closest('variant-selects') ||
        t.closest('product-form')
      ) {
        setTimeout(() => refreshPrice("variant change"), 200);
      }
    });

    document.addEventListener("variant:change", () => {
      setTimeout(() => refreshPrice("variant:change event"), 100);
    });

    document.addEventListener("shopify:section:load", () => {
      setTimeout(() => refreshPrice("section load"), 200);
    });

    // Broad fallback: if our injected price element disappears and the targeted
    // observer hasn't caught it yet (e.g. during a full section re-render),
    // queue a fresh fetch.
    const broadObserver = new MutationObserver(() => {
      const node = chooseMainPriceNode();
      if (!node) return;
      if (!document.querySelector(".priceguard-final-price")) {
        setTimeout(() => refreshPrice("mutation observer"), 100);
      }
    });

    broadObserver.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  function init() {
    refreshPrice("init");
    wireVariantListeners();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
