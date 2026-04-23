-- Rename legacy 'premium' plan to 'pro' to match new three-tier naming
UPDATE shops SET plan_name = 'pro' WHERE plan_name = 'premium';
