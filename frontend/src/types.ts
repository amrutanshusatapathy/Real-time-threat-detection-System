export type ThreatType =
  | 'DDoS'
  | 'Port Scan'
  | 'SQL Injection'
  | 'XSS'
  | 'Brute Force'
  | 'Botnet'
  | 'Suspicious Spike'
  | 'Anomaly'

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface ThreatEvent {
  id: string
  ts: string
  srcIp: string
  type: ThreatType
  severity: Severity
  target: string
  blocked: boolean
  anomalyScore?: number

  geo: {
    country: string
    city: string
    lat: number
    lon: number
  }
}

export interface OverviewStats {
  totalThreats: number
  blockedIps: number
  anomalyAlerts: number
  activeConnections: number
}

export interface NetworkStats {
  packetsPerSecond: number
  bandwidthMbps: number
  activeConnections: number
}

export interface DashboardSnapshot {
  overview: OverviewStats
  threats: ThreatEvent[]
  network: NetworkStats
  highSeverityAlerts: ThreatEvent[]
}
