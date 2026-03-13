from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    app_name: str = "Real-Time Network Threat Detection Platform"

    # CORS (for browser-based frontends like Netlify)
    # Comma-separated list of origins, or "*".
    # Example: "https://your-site.netlify.app,https://your-custom-domain.com"
    cors_allow_origins: str = "*"
    cors_allow_credentials: bool = False
    cors_allow_methods: str = "*"
    cors_allow_headers: str = "*"

    redis_url: str = "redis://localhost:6379/0"

    # Database
    # If set, overrides sqlite_path (recommended for Docker/production).
    # Example: postgresql+psycopg2://user:pass@postgres:5432/threats
    database_url: str | None = None
    sqlite_path: str = "./data/threats.db"

    capture_enabled: bool = False
    capture_iface: str | None = None

    # Stream + channel names
    stream_packets: str = "packets.raw"
    stream_alerts: str = "alerts.stream"
    channel_live_alerts: str = "alerts.live"
    blocklist_set: str = "blocklist.ips"

    # Worker tuning
    worker_poll_block_ms: int = 2000
    worker_batch_count: int = 200

    # ML model paths
    models_dir: str = "./data/models"

    # Optional: use a standalone ML inference service instead of local sklearn models.
    # Example: http://ml:9000
    ml_service_url: str | None = None


settings = Settings()
