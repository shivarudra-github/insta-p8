import { register } from "node:module"

// Set test environment variables BEFORE any application modules load
process.env.SESSION_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
process.env.INSTAGRAM_WEBHOOK_VERIFY_TOKEN = "test_webhook_verify_token_123"
process.env.INSTAGRAM_APP_SECRET = "test_meta_app_secret_456"

register("./loader.mjs", import.meta.url)
