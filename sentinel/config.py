"""Central configuration. All values overridable via environment / .env."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_", extra="ignore")

    # Storage
    database_url: str = "sqlite:///./sentinel.db"

    # Control-plane auth. Unset (default) means the API is unauthenticated —
    # fine for local dev against your own machine, NOT fine for anything
    # reachable by anyone else: Phase 0 verifies DOMAIN ownership, never
    # CALLER identity, so without this set any caller who can reach the API
    # can start/halt scans or deregister targets someone else registered.
    api_key: str | None = None

    # LLM — set exactly one. Precedence: anthropic > openrouter > openai.
    # OpenRouter is OpenAI-API-compatible, reached via the openai SDK with a
    # base_url override; its model IDs are "provider/model", e.g.
    # "anthropic/claude-sonnet-4.5" or "openai/gpt-4o-mini" — set llm_model
    # accordingly when using it (the default below is Anthropic-native and
    # will 404 against OpenRouter).
    anthropic_api_key: str | None = None
    openrouter_api_key: str | None = None
    openai_api_key: str | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    llm_model: str = "claude-sonnet-4-5"

    # Scan engines
    nuclei_binary_path: str = "nuclei"
    nuclei_templates_path: str | None = None
    nuclei_timeout_seconds: int = 300
    zap_api_url: str = "http://localhost:8080"
    zap_api_key: str | None = None
    zap_spider_timeout_seconds: float = 180.0
    zap_ascan_timeout_seconds: float = 600.0

    # Phase 0 verification
    verification_http_timeout_seconds: float = 10.0
    verification_dns_timeout_seconds: float = 5.0
    well_known_path: str = "/.well-known/sentinel-auth.txt"
    dns_txt_prefix: str = "_sentinel-verify"

    # Rate limiting / recon
    recon_max_requests_per_second: float = 5.0
    recon_max_pages: int = 500

    # Kill switch / anomaly thresholds
    killswitch_error_rate_threshold: float = 0.35
    killswitch_latency_multiplier: float = 4.0
    killswitch_min_samples: int = 20

    # Audit log
    audit_log_file: str = "./audit_log.ndjson"
    # Unset -> plain SHA-256 (tamper-evident only against parties without DB
    # write access). Set to a secret stored OUTSIDE the database to switch to
    # HMAC-SHA256, so forging a valid chain after editing a row requires this
    # key, not just DB access. See sentinel/security/audit_log.py docstring.
    audit_log_hmac_key: str | None = None


settings = Settings()
