"""Central configuration. All values overridable via environment / .env."""
from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_", extra="ignore")

    # Storage
    database_url: str = "sqlite:///./sentinel.db"

    # Control-plane auth. The HTTP API fails closed when this is absent.
    # This global key is suitable only for a single-operator MVP: Phase 0
    # verifies domain ownership, not caller identity or tenant ownership.
    # Production needs authenticated, tenant- and asset-scoped principals.
    api_key: str | None = None

    # Authorization-control-plane integrity. This must be an independent
    # secret (environment or secrets manager), never a database field: it
    # signs the immutable policy fields in a scan contract. Contract-backed
    # runs fail closed when it is not configured.
    control_plane_signing_key: str | None = None
    # A lease is deliberately short-lived even if a contract lasts longer.
    # The service also has a code-level 15 minute ceiling.
    control_plane_max_lease_seconds: int = 900

    # Customer-hosted runner permits are signed asymmetrically. This is an
    # Ed25519 *private* key encoded as unpadded URL-safe base64 raw bytes.
    # It stays in the control-plane secret manager; customer runners receive
    # a separately pinned derived public verification key during onboarding.
    # The permit API returns only a non-secret issuer key ID. Do not reuse
    # control_plane_signing_key here: that key is HMAC/symmetric.
    runner_permit_private_key: str | None = None
    # A fail-closed deployment classification. The temporary shared-key
    # permit endpoint can run only in an explicitly marked development
    # deployment; customer or production deployments must remain production.
    deployment_mode: Literal["development", "production"] = "production"
    # The current permit endpoint is only a local/operator development aid.
    # Keep it disabled by default so an accidentally exposed MVP cannot mint
    # customer-runner permits. Production must replace it with enrolled,
    # tenant-scoped runner identity rather than enabling this flag.
    enable_development_runner_permit_issuance: bool = False

    # LLM — set exactly one. Precedence: anthropic > tokenrouter >
    # openrouter > openai.
    #
    # TokenRouter is OpenAI-API-compatible.  The default is the project's
    # selected GLM route; its structured-triage request uses an explicit JSON
    # instruction rather than assuming every provider supports JSON mode.
    # OpenRouter is OpenAI-API-compatible, reached via the openai SDK with a
    # base_url override; its model IDs are "provider/model", e.g.
    # "anthropic/claude-sonnet-4.5" or "openai/gpt-4o-mini" — set llm_model
    # accordingly when using it (the default below is Anthropic-native and
    # will 404 against OpenRouter).
    anthropic_api_key: str | None = None
    tokenrouter_api_key: str | None = None
    tokenrouter_base_url: str = "https://api.tokenrouter.com/v1"
    tokenrouter_model: str = "z-ai/glm-5.2-free"
    openrouter_api_key: str | None = None
    openai_api_key: str | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    llm_model: str = "claude-sonnet-4-5"
    # Optional operational cap for a deliberately small AI preview.  Normal
    # runs leave this unset; the local two-minute demo sets it to six.
    llm_max_cwe_judgments: int | None = None

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
