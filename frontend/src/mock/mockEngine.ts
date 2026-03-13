import type {
  DashboardSnapshot,
  NetworkStats,
  OverviewStats,
  Severity,
  ThreatEvent,
  ThreatType,
} from '../types'
import { clamp } from '../lib/format'

type Geo = ThreatEvent['geo']

type MockState = {
  threats: ThreatEvent[]
  overview: OverviewStats
  network: NetworkStats
  blockedIpSet: Set<string>
}

const THREAT_TYPES: ThreatType[] = [
  'DDoS',
  'Port Scan',
  'SQL Injection',
  'XSS',
  'Brute Force',
]

const TARGETS = [
  '/login',
  '/api/auth',
  '/api/v1/users',
  '/api/v1/orders',
  '/admin',
  '/wp-login.php',
  '/.env',
  '/../etc/passwd',
  '/search?q=<script>',
  '/api/graphql',
]

const GEO_LOCATIONS: Geo[] = [
  { city: 'New York', country: 'US', lat: 40.7128, lon: -74.006 },
  { city: 'San Francisco', country: 'US', lat: 37.7749, lon: -122.4194 },
  { city: 'London', country: 'GB', lat: 51.5072, lon: -0.1276 },
  { city: 'Frankfurt', country: 'DE', lat: 50.1109, lon: 8.6821 },
  { city: 'Amsterdam', country: 'NL', lat: 52.3676, lon: 4.9041 },
  { city: 'Paris', country: 'FR', lat: 48.8566, lon: 2.3522 },
  { city: 'Warsaw', country: 'PL', lat: 52.2297, lon: 21.0122 },
  { city: 'São Paulo', country: 'BR', lat: -23.5558, lon: -46.6396 },
  { city: 'Mexico City', country: 'MX', lat: 19.4326, lon: -99.1332 },
  { city: 'Johannesburg', country: 'ZA', lat: -26.2041, lon: 28.0473 },
  { city: 'Lagos', country: 'NG', lat: 6.5244, lon: 3.3792 },
  { city: 'Mumbai', country: 'IN', lat: 19.076, lon: 72.8777 },
  { city: 'Singapore', country: 'SG', lat: 1.3521, lon: 103.8198 },
  { city: 'Tokyo', country: 'JP', lat: 35.6762, lon: 139.6503 },
  { city: 'Seoul', country: 'KR', lat: 37.5665, lon: 126.978 },
  { city: 'Sydney', country: 'AU', lat: -33.8688, lon: 151.2093 },
]

function pick<T>(items: T[]): T {
  return items[Math.floor(Math.random() * items.length)]!
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function randomIp(): string {
  const a = pick([23, 31, 45, 58, 77, 89, 103, 109, 141, 176, 185, 203])
  const b = randomInt(0, 255)
  const c = randomInt(0, 255)
  const d = randomInt(1, 254)
  return `${a}.${b}.${c}.${d}`
}

function severityByType(type: ThreatType): Severity {
  // Weighted, but still varied enough for demos
  const r = Math.random()
  if (type === 'SQL Injection' || type === 'DDoS') {
    if (r < 0.15) return 'CRITICAL'
    if (r < 0.55) return 'HIGH'
    if (r < 0.9) return 'MEDIUM'
    return 'LOW'
  }
  if (type === 'Brute Force') {
    if (r < 0.08) return 'CRITICAL'
    if (r < 0.45) return 'HIGH'
    if (r < 0.88) return 'MEDIUM'
    return 'LOW'
  }
  if (type === 'Port Scan') {
    if (r < 0.05) return 'CRITICAL'
    if (r < 0.3) return 'HIGH'
    if (r < 0.85) return 'MEDIUM'
    return 'LOW'
  }
  // XSS
  if (r < 0.05) return 'CRITICAL'
  if (r < 0.35) return 'HIGH'
  if (r < 0.85) return 'MEDIUM'
  return 'LOW'
}

function anomalyScoreBySeverity(sev: Severity): number | undefined {
  const r = Math.random()
  if (sev === 'LOW') return r < 0.12 ? 0.65 + Math.random() * 0.1 : undefined
  if (sev === 'MEDIUM') return r < 0.22 ? 0.72 + Math.random() * 0.12 : undefined
  if (sev === 'HIGH') return 0.82 + Math.random() * 0.14
  return 0.9 + Math.random() * 0.09
}

function shouldBlock(sev: Severity, type: ThreatType): boolean {
  if (sev === 'CRITICAL') return true
  if (sev === 'HIGH') return Math.random() < 0.55
  if (type === 'Brute Force' && sev === 'MEDIUM') return Math.random() < 0.25
  return Math.random() < 0.06
}

function createThreatEvent(now: Date): ThreatEvent {
  const type = pick(THREAT_TYPES)
  const severity = severityByType(type)
  const target = pick(TARGETS)
  const geo = pick(GEO_LOCATIONS)
  const srcIp = randomIp()
  const blocked = shouldBlock(severity, type)
  const anomalyScore = anomalyScoreBySeverity(severity)

  return {
    id: `T-${now.getTime()}-${Math.random().toString(16).slice(2, 8)}`,
    ts: now.toISOString(),
    srcIp,
    type,
    severity,
    target,
    blocked,
    anomalyScore,
    geo,
  }
}

function updateNetwork(prev: NetworkStats, newThreatCount: number): NetworkStats {
  const spike = newThreatCount > 1 ? 1.08 : 1
  const jitterPps = (Math.random() - 0.5) * 140
  const jitterBw = (Math.random() - 0.5) * 10
  const jitterConn = (Math.random() - 0.5) * 30

  return {
    packetsPerSecond: Math.round(
      clamp(prev.packetsPerSecond * 0.92 + (1100 + jitterPps) * 0.08, 250, 6000) *
        spike,
    ),
    bandwidthMbps: clamp(
      prev.bandwidthMbps * 0.9 + (75 + jitterBw) * 0.1,
      8,
      950,
    ),
    activeConnections: Math.round(
      clamp(prev.activeConnections * 0.92 + (420 + jitterConn) * 0.08, 50, 5000),
    ),
  }
}

function computeOverview(
  state: Pick<MockState, 'overview' | 'blockedIpSet' | 'network' | 'threats'>,
): OverviewStats {
  const anomalyAlerts = state.threats.reduce(
    (acc, t) => acc + (t.anomalyScore !== undefined && t.anomalyScore >= 0.85 ? 1 : 0),
    0,
  )

  return {
    totalThreats: state.overview.totalThreats,
    blockedIps: state.blockedIpSet.size,
    anomalyAlerts,
    activeConnections: state.network.activeConnections,
  }
}

function highSeverity(threats: ThreatEvent[]): ThreatEvent[] {
  return threats
    .filter((t) => t.severity === 'HIGH' || t.severity === 'CRITICAL')
    .slice(-8)
    .reverse()
}

export function createMockEngine(initialThreats = 80): {
  snapshot: () => DashboardSnapshot
  tick: () => DashboardSnapshot
} {
  const state: MockState = {
    threats: [],
    blockedIpSet: new Set<string>(),
    overview: {
      totalThreats: 0,
      blockedIps: 0,
      anomalyAlerts: 0,
      activeConnections: 0,
    },
    network: {
      packetsPerSecond: 1150,
      bandwidthMbps: 82,
      activeConnections: 430,
    },
  }

  const seedNow = Date.now()
  for (let i = initialThreats; i > 0; i -= 1) {
    const when = new Date(seedNow - i * 2200)
    const event = createThreatEvent(when)
    state.threats.push(event)
    state.overview.totalThreats += 1
    if (event.blocked) state.blockedIpSet.add(event.srcIp)
  }

  state.network = updateNetwork(state.network, 1)
  state.overview = computeOverview(state)

  function snapshot(): DashboardSnapshot {
    return {
      overview: computeOverview(state),
      threats: state.threats.slice(-250),
      network: state.network,
      highSeverityAlerts: highSeverity(state.threats),
    }
  }

  function tick(): DashboardSnapshot {
    const now = new Date()
    const newThreatCount = Math.random() < 0.25 ? 2 : 1

    for (let i = 0; i < newThreatCount; i += 1) {
      const event = createThreatEvent(new Date(now.getTime() - i * 150))
      state.threats.push(event)
      state.overview.totalThreats += 1
      if (event.blocked) state.blockedIpSet.add(event.srcIp)
    }

    // Cap stored items to keep charts smooth
    if (state.threats.length > 700) state.threats = state.threats.slice(-500)

    state.network = updateNetwork(state.network, newThreatCount)
    state.overview = computeOverview(state)

    return snapshot()
  }

  return { snapshot, tick }
}
