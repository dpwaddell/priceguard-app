CREATE TABLE IF NOT EXISTS shops (
  id BIGSERIAL PRIMARY KEY,
  shop_domain TEXT NOT NULL UNIQUE,
  access_token TEXT,
  refresh_token TEXT,
  token_expires_at TIMESTAMPTZ,
  installed_at TIMESTAMPTZ,
  uninstalled_at TIMESTAMPTZ,
  plan_name TEXT DEFAULT 'free',
  plan_status TEXT DEFAULT 'inactive',
  currency TEXT,
  timezone TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE shops ADD COLUMN IF NOT EXISTS refresh_token TEXT;
ALTER TABLE shops ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS settings (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT NOT NULL UNIQUE REFERENCES shops(id) ON DELETE CASCADE,
  app_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  onboarding_complete BOOLEAN NOT NULL DEFAULT FALSE,
  free_plan_customer_limit INTEGER NOT NULL DEFAULT 1,
  pricing_display_mode TEXT NOT NULL DEFAULT 'replace',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_sessions (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT REFERENCES shops(id) ON DELETE CASCADE,
  session_key TEXT NOT NULL UNIQUE,
  session_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pricing_tiers (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  customer_tag TEXT,
  discount_type TEXT NOT NULL CHECK (discount_type IN ('percentage','fixed_amount')),
  discount_value NUMERIC(12,2) NOT NULL,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  starts_at TIMESTAMPTZ,
  ends_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pricing_tiers_shop_id ON pricing_tiers(shop_id);

CREATE TABLE IF NOT EXISTS customer_assignments (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
  shopify_customer_id TEXT,
  customer_email TEXT NOT NULL,
  tier_id BIGINT NOT NULL REFERENCES pricing_tiers(id) ON DELETE CASCADE,
  starts_at TIMESTAMPTZ,
  ends_at TIMESTAMPTZ,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (shop_id, customer_email, tier_id, starts_at)
);

CREATE INDEX IF NOT EXISTS idx_customer_assignments_shop_email ON customer_assignments(shop_id, customer_email);

CREATE TABLE IF NOT EXISTS customer_product_prices (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
  shopify_customer_id TEXT,
  customer_email TEXT NOT NULL,
  product_id TEXT,
  variant_id TEXT,
  sku TEXT NOT NULL,
  fixed_price NUMERIC(12,2) NOT NULL,
  currency TEXT,
  starts_at TIMESTAMPTZ,
  ends_at TIMESTAMPTZ,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_customer_product_prices_shop_email_sku
  ON customer_product_prices(shop_id, customer_email, sku);

CREATE TABLE IF NOT EXISTS collection_rules (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
  tier_id BIGINT NOT NULL REFERENCES pricing_tiers(id) ON DELETE CASCADE,
  collection_id TEXT,
  collection_handle TEXT,
  discount_type TEXT NOT NULL CHECK (discount_type IN ('percentage','fixed_amount')),
  discount_value NUMERIC(12,2) NOT NULL,
  starts_at TIMESTAMPTZ,
  ends_at TIMESTAMPTZ,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_collection_rules_shop_tier ON collection_rules(shop_id, tier_id);

CREATE TABLE IF NOT EXISTS imports (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
  import_type TEXT NOT NULL CHECK (import_type IN ('customer_prices','tier_assignments','collection_rules')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','completed','completed_with_errors','failed')),
  filename TEXT,
  total_rows INTEGER NOT NULL DEFAULT 0,
  success_rows INTEGER NOT NULL DEFAULT 0,
  failed_rows INTEGER NOT NULL DEFAULT 0,
  error_summary TEXT,
  import_mode TEXT NOT NULL DEFAULT 'upsert' CHECK (import_mode IN ('create_only','upsert','replace_matching')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  shop_id BIGINT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
  actor_type TEXT NOT NULL DEFAULT 'system',
  actor_email TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_shop_created_at ON audit_logs(shop_id, created_at DESC);
