import { useEffect, useMemo, useRef, useState } from 'react'
import type { DashboardSnapshot, NetworkStats, ThreatEvent, ThreatType } from '../types'

type ApiAlert = {
  id: number
  ts: string
  src_ip: string
  dst_ip?: string | null
  dst_port?: number | null
  attack_type: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  blocked: boolean
  anomaly_score?: number | null
  details?: Record<string, unknown>
}

type ApiBlockedIp = {
  ip: string
  blocked_at: string
  reason?: string | null
}

type ApiNetworkStats = {
  ts: string
  packets_per_second: number
  bandwidth_mbps: number
  active_connections: number
}

function env(name: string): string | undefined {
  const v = (import.meta as any).env?.[name]
  return typeof v === 'string' && v.length ? v : undefined
}

function normalizeBaseUrl(value: string): string {
  // Avoid accidental double slashes when composing endpoint URLs.
  // Example: "https://api.example.com/" -> "https://api.example.com"
  const trimmed = value.trim().replace(/\/+$/, '')
  if (/^https?:\/\//i.test(trimmed)) return trimmed
  // Common deployment footgun: user pastes "example.onrender.com" without protocol.
  return `https://${trimmed}`
}

function apiBase(): string {
  return normalizeBaseUrl(env('VITE_API_BASE_URL') ?? 'http://localhost:8000')
}

function wsUrl(): string {
  const explicit = env('VITE_WS_URL')
  if (explicit) return explicit
  // Derive from API base
  const base = apiBase()
  const u = new URL(base)
  const proto = u.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${u.host}/ws/alerts`
}

function coerceThreatType(value: string): ThreatType {
  const v = value as ThreatType
  // Keep UI stable: treat unexpected types as 'Anomaly'
  const allowed: ThreatType[] = [
    'DDoS',
    'Port Scan',
    'SQL Injection',
    'XSS',
    'Brute Force',
    'Botnet',
    'Suspicious Spike',
    'Anomaly',
  ]
  return allowed.includes(v) ? v : 'Anomaly'
}

function toThreatEvent(a: ApiAlert): ThreatEvent {
  const target = a.dst_ip ? `${a.dst_ip}${a.dst_port ? `:${a.dst_port}` : ''}` : 'unknown'

  const ts = typeof a.ts === 'string' && a.ts.length ? a.ts : new Date().toISOString()
  const safeTs = Number.isNaN(new Date(ts).getTime()) ? new Date().toISOString() : ts

  return {
    id: String(a.id),
    ts: safeTs,
    srcIp: a.src_ip,
    type: coerceThreatType(a.attack_type),
    severity: a.severity,
    target,
    blocked: Boolean(a.blocked),
    anomalyScore: a.anomaly_score ?? undefined,
    // Geo is optional in backend right now; keep deterministic placeholders
    geo: {
      country: 'UN',
      city: 'Unknown',
      lat: 0,
      lon: 0,
    },
  }
}

function emptySnapshot(): DashboardSnapshot {
  return {
    overview: {
      totalThreats: 0,
      blockedIps: 0,
      anomalyAlerts: 0,
      activeConnections: 0,
    },
    threats: [],
    network: {
      packetsPerSecond: 0,
      bandwidthMbps: 0,
      activeConnections: 0,
    },
    highSeverityAlerts: [],
  }
}

function derive(snapshot: DashboardSnapshot): DashboardSnapshot {
  const threats = snapshot.threats
  const anomalyAlerts = threats.filter((t) => t.type === 'Anomaly').length
  const highSeverityAlerts = threats.filter((t) => t.severity === 'HIGH' || t.severity === 'CRITICAL')

  return {
    ...snapshot,
    overview: {
      ...snapshot.overview,
      totalThreats: threats.length,
      anomalyAlerts,
      activeConnections: snapshot.network.activeConnections,
    },
    highSeverityAlerts: highSeverityAlerts.slice(0, 20),
  }
}

export function useDashboardApi(): DashboardSnapshot {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(() => emptySnapshot())
  const wsRef = useRef<WebSocket | null>(null)

  const base = useMemo(() => apiBase(), [])
  const ws = useMemo(() => wsUrl(), [])

  useEffect(() => {
    let cancelled = false

    async function loadInitial(): Promise<void> {
      const [threatsRes, netRes, blockedRes] = await Promise.all([
        fetch(`${base}/get-threats?limit=250`),
        fetch(`${base}/get-network-stats`),
        fetch(`${base}/get-blocked-ips?limit=500`),
      ])

      const threatsJson = (await threatsRes.json()) as ApiAlert[]
      const netJson = (await netRes.json()) as ApiNetworkStats
      const blockedJson = (await blockedRes.json()) as ApiBlockedIp[]

      if (cancelled) return

      const threats: ThreatEvent[] = Array.isArray(threatsJson) ? threatsJson.map(toThreatEvent) : []
      const network: NetworkStats = {
        packetsPerSecond: Number(netJson.packets_per_second ?? 0),
        bandwidthMbps: Number(netJson.bandwidth_mbps ?? 0),
        activeConnections: Number(netJson.active_connections ?? 0),
      }

      const next: DashboardSnapshot = derive({
        ...emptySnapshot(),
        threats,
        network,
        overview: {
          ...emptySnapshot().overview,
          blockedIps: Array.isArray(blockedJson) ? blockedJson.length : 0,
          activeConnections: network.activeConnections,
        },
      })

      setSnapshot(next)
    }

    loadInitial().catch(() => {
      if (!cancelled) setSnapshot((s) => s)
    })

    return () => {
      cancelled = true
    }
  }, [base])

  useEffect(() => {
    // Poll network stats lightly to keep charts alive
    const id = window.setInterval(async () => {
      try {
        const res = await fetch(`${base}/get-network-stats`)
        const netJson = (await res.json()) as ApiNetworkStats
        const network: NetworkStats = {
          packetsPerSecond: Number(netJson.packets_per_second ?? 0),
          bandwidthMbps: Number(netJson.bandwidth_mbps ?? 0),
          activeConnections: Number(netJson.active_connections ?? 0),
        }

        setSnapshot((prev) => derive({
          ...prev,
          network,
          overview: {
            ...prev.overview,
            activeConnections: network.activeConnections,
          },
        }))
      } catch {
        // ignore
      }
    }, 1500)

    return () => window.clearInterval(id)
  }, [base])

  useEffect(() => {
    const socket = new WebSocket(ws)
    wsRef.current = socket

    socket.onmessage = (evt) => {
      try {
        const raw = JSON.parse(String(evt.data)) as ApiAlert
        const event = toThreatEvent(raw)

        setSnapshot((prev) => {
          const threats = [event, ...prev.threats].slice(0, 500)
          const blockedIps = prev.overview.blockedIps + (event.blocked ? 1 : 0)
          return derive({
            ...prev,
            threats,
            overview: {
              ...prev.overview,
              blockedIps,
            },
          })
        })
      } catch {
        // ignore malformed messages
      }
    }

    socket.onerror = () => {
      // ignore
    }

    return () => {
      try {
        socket.close()
      } catch {
        // ignore
      }
      wsRef.current = null
    }
  }, [ws])

  return snapshot
}
