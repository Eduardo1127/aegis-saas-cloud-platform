#!/usr/bin/env python3
"""
AEGIS PRIME SAAS CLOUD PLATFORM - CONFIGURATION & STRIPE API KEYS
Author: Eduardo Mexquitic Rodriguez (EMR)
"""

import os

SECRET_KEY = os.environ.get("SECRET_KEY", "AEGIS_SAAS_SUPER_SECRET_JWT_KEY_2026_EMR")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

# Telegram Telemetry
TELEGRAM_BOT_TOKEN = "8893915158:AAFWy8WTn2sXP0_GXgRFEKsOkGtMeOfpie0"
TELEGRAM_CHAT_ID = "8926630685"

# Official Live Stripe API Keys (Read securely from Environment Variables on Cloud Server)
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "pk_test_51U2PHdDAaoULbJgOH8olrp6xjsJud7AmXO8VLLlE4j9K7kvWd8LjhSIjrDmdLwW8xLTgZVetBmzv78Pbey78gjO100fmnEdtrw")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")

# Pricing Tiers (USD)
TIERS = {
    "basic": {"name": "Basic Edition", "price": 29.00, "scans_per_month": 50, "support": "Standard"},
    "pro": {"name": "Professional Edition", "price": 79.00, "scans_per_month": 500, "support": "Priority 24/7"},
    "enterprise": {"name": "Enterprise Master SOC", "price": 149.00, "scans_per_month": "Unlimited", "support": "Dedicated CISO & AI Copilot"}
}
