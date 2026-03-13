# Deployment Guide — Real-Time Threat Detection System

## Local deployment (Docker Compose)

Prereqs:
- Docker Desktop

Run:

```bash
docker compose up --build
```

Services:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000 (docs at `/docs`)
- Prometheus: http://localhost:9090
- Postgres: localhost:5432
- Redis: localhost:6379
- ML service: http://localhost:9000

### Environment variables

- Copy `.env.example` → `.env` (do not commit `.env`)
- For production, use your hosting provider’s secret manager (Render/Vercel/AWS).

CORS (Backend, for browser frontends like Netlify):

- `CORS_ALLOW_ORIGINS` (comma-separated list, or `*`)
  - Example: `https://your-site.netlify.app`
- `CORS_ALLOW_CREDENTIALS` (default: false)

Beginner-friendly hosted setup (recommended):

- Frontend: Netlify
- Backend: Render (Docker)
- Postgres: Neon (free tier)
- Redis: Upstash (free tier)

## Monitoring (Prometheus)

The backend exposes `/metrics` with:
- `threatd_packet_rate_pps`
- `threatd_detected_attacks_total{attack_type=...}`
- `threatd_blocked_ip_events_total`
- `threatd_blocklist_size`

Prometheus is configured in `prometheus/prometheus.yml`.

## Deployment options

### Frontend (Vercel or Netlify)

Build settings:
- Root directory: `frontend`
- Install command: `npm ci` (or `npm install`)
- Build command: `npm run build`
- Output directory: `dist`

Runtime config:

- Set `VITE_USE_MOCK=false`
- Set `VITE_API_BASE_URL` to your backend API base URL:
  - Example: `https://<your-backend-host>`
- Optional: set `VITE_WS_URL` explicitly (otherwise it is derived from `VITE_API_BASE_URL`):
  - Example: `wss://<your-backend-host>/ws/alerts`

Netlify notes:

- This repo includes a root `netlify.toml` (base=`frontend`, publish=`dist`) and an SPA redirect.

### Backend (Render or AWS)

Recommended approach: deploy the backend as a Docker service.

Required environment variables:
- `REDIS_URL`
- `DATABASE_URL` (PostgreSQL)

Optional environment variables:
- `ML_SERVICE_URL` (URL to the ML service). If unset, the backend uses the bundled sklearn models.
- `CORS_ALLOW_ORIGINS` (set to your Netlify site URL, e.g. `https://your-site.netlify.app`)

Database:
- Use managed Postgres (Render Postgres / AWS RDS).
- The backend auto-creates tables on startup (`init_db`).

Redis:
- Use managed Redis (Render Redis / AWS ElastiCache) or self-host.

Health and metrics:
- Health: `/`
- Metrics: `/metrics`

Beginner (recommended): Render + Neon + Upstash

1) Create Postgres on Neon

- Create a Neon project and copy the connection string.
- Convert it to SQLAlchemy format (example):
  - `postgresql+psycopg2://USER:PASSWORD@HOST/DB?sslmode=require`

2) Create Redis on Upstash

- Create a Redis database and copy the connection URL.

3) Deploy backend on Render

- Render → New → Web Service → connect your GitHub repo
- Root directory: `backend`
- Environment: Docker
- Port: `8000`
- Env vars:
  - `DATABASE_URL` (Neon)
  - `REDIS_URL` (Upstash)
  - `CORS_ALLOW_ORIGINS` (your Netlify URL)
  - `CAPTURE_ENABLED=false` (cloud hosts can’t sniff packets)

Notes about ML models on cloud:

- This repo ignores `backend/data/` by default (so databases/models aren’t committed).
- On first boot, the backend auto-generates demo models if `./data/models/*.joblib` is missing.
- If you want to deploy your trained CICIDS2018 models, generate them locally and commit only the `*.joblib` files (or store them in object storage and download on startup).

4) Point Netlify at the backend

- In Netlify env vars, set `VITE_API_BASE_URL` to the Render service URL.

### ML service (Render/AWS)

Deploy `ml_service` as a separate Docker service.

Environment variables:
- `MODELS_DIR=/models`

Models:

- Models are baked into the ML Docker image by default (copied to `/models`).
- To override locally, set `MODELS_DIR` and mount a volume with your own `*.joblib` files.
- For managed deployments with frequent retraining, store artifacts in object storage (S3) and download on startup, or use a persistent disk.

Endpoints:
- `POST /predict`
- `GET /metrics`

## Security notes

- Do not commit secrets into the repo.
- Prefer platform secrets (Render “Environment”, Vercel “Environment Variables”, AWS Secrets Manager).
- If you need Docker secrets, add them to Compose and read from files at runtime.
