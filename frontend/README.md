# Real-Time Threat Detection System — SOC Dashboard (Frontend)

Modern cybersecurity dashboard built with:

- React + Vite + TypeScript
- TailwindCSS
- Chart.js (via react-chartjs-2)
- Leaflet (via react-leaflet) for global attack map

## Run locally

```bash
npm install
npm run dev
```

Open: http://localhost:5173

## Mock data (works immediately)

By default the dashboard runs on a mock real-time stream so the UI works without a backend.

- Mock stream is implemented in `src/mock/mockEngine.ts`
- The hook `src/hooks/useDashboardMock.ts` ticks once per second

## Wiring a backend later

When your backend endpoints are ready, you can switch off the mock stream:

```bash
VITE_USE_MOCK=false
```

Backend wiring is implemented via `src/hooks/useDashboardApi.ts`.

Required env vars:

- `VITE_USE_MOCK=false`
- `VITE_API_BASE_URL` (default: `http://localhost:8000`)
- `VITE_WS_URL` (optional; if omitted it is derived from `VITE_API_BASE_URL`)

## Deploy on Netlify

This repo includes a root `netlify.toml` that configures Netlify to build the Vite app from `frontend/`.

Set env vars in Netlify:

- `VITE_USE_MOCK=false`
- `VITE_API_BASE_URL=https://<your-backend-host>`
- (optional) `VITE_WS_URL=wss://<your-backend-host>/ws/alerts`
