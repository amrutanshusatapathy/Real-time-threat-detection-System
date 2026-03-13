import type { ReactNode } from 'react'
import { useMemo } from 'react'
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js'
import { Bar, Doughnut, Line, Pie } from 'react-chartjs-2'
import type { Severity, ThreatEvent, ThreatType } from '../types'
import { Panel } from './Panel'

ChartJS.register(
  CategoryScale,
  LinearScale,
  ArcElement,
  PointElement,
  LineElement,
  BarElement,
  Tooltip,
  Legend,
  Filler,
)

const COLORS = {
  cyan: 'rgb(34 211 238)',
  blue: 'rgb(59 130 246)',
  emerald: 'rgb(52 211 153)',
  amber: 'rgb(245 158 11)',
  orange: 'rgb(249 115 22)',
  red: 'rgb(239 68 68)',
  slate: 'rgb(148 163 184)',
  grid: 'rgba(148 163 184 / 0.12)',
}

const chartCommon = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color: COLORS.slate,
        boxWidth: 10,
        boxHeight: 10,
      },
    },
    tooltip: {
      backgroundColor: 'rgba(2 6 23 / 0.95)',
      titleColor: 'rgb(226 232 240)',
      bodyColor: 'rgb(203 213 225)',
      borderColor: 'rgba(34 211 238 / 0.18)',
      borderWidth: 1,
    },
  },
  scales: {
    x: {
      ticks: { color: COLORS.slate },
      grid: { color: 'transparent' },
    },
    y: {
      ticks: { color: COLORS.slate },
      grid: { color: COLORS.grid },
    },
  },
} as const

function countByType(threats: ThreatEvent[]): Record<ThreatType, number> {
  const out = {
    'DDoS': 0,
    'Port Scan': 0,
    'SQL Injection': 0,
    'XSS': 0,
    'Brute Force': 0,
    'Botnet': 0,
    'Suspicious Spike': 0,
    'Anomaly': 0,
  } satisfies Record<ThreatType, number>

  for (const t of threats) out[t.type] += 1
  return out
}

function countBySeverity(threats: ThreatEvent[]): Record<Severity, number> {
  const out = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  } satisfies Record<Severity, number>

  for (const t of threats) out[t.severity] += 1
  return out
}

function topIps(threats: ThreatEvent[], limit = 6): Array<{ ip: string; count: number }> {
  const counts = new Map<string, number>()
  for (const t of threats) counts.set(t.srcIp, (counts.get(t.srcIp) ?? 0) + 1)

  return [...counts.entries()]
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
}

function timelineBuckets(threats: ThreatEvent[], minutes = 15): { labels: string[]; values: number[] } {
  const now = Date.now()
  const bucketMs = 60_000
  const buckets = new Array(minutes).fill(0)

  for (const t of threats) {
    const ts = new Date(t.ts).getTime()
    const delta = now - ts
    if (delta < 0) continue
    const bucketIndexFromNow = Math.floor(delta / bucketMs)
    const idx = minutes - 1 - bucketIndexFromNow
    if (idx >= 0 && idx < minutes) buckets[idx] += 1
  }

  const labels = [] as string[]
  for (let i = minutes - 1; i >= 0; i -= 1) {
    const d = new Date(now - i * bucketMs)
    labels.push(
      d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
    )
  }

  return { labels, values: buckets }
}

export function ThreatCharts(props: { threats: ThreatEvent[] }): ReactNode {
  const { threats } = props

  const last = useMemo(() => threats.slice(-250), [threats])

  const byType = useMemo(() => countByType(last), [last])
  const bySev = useMemo(() => countBySeverity(last), [last])
  const top = useMemo(() => topIps(last, 7), [last])
  const timeline = useMemo(() => timelineBuckets(last, 15), [last])

  const typeLabels = Object.keys(byType) as ThreatType[]
  const typeValues = typeLabels.map((k) => byType[k])

  const severityLabels: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
  const severityValues = severityLabels.map((k) => bySev[k])

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Panel title="Threats by Type" subtitle="Distribution across categories">
        <div className="h-[260px]">
          <Pie
            data={{
              labels: typeLabels,
              datasets: [
                {
                  data: typeValues,
                  backgroundColor: [
                    'rgba(34 211 238 / 0.35)',
                    'rgba(59 130 246 / 0.35)',
                    'rgba(239 68 68 / 0.35)',
                    'rgba(245 158 11 / 0.35)',
                    'rgba(249 115 22 / 0.35)',
                  ],
                  borderColor: [
                    'rgba(34 211 238 / 0.7)',
                    'rgba(59 130 246 / 0.7)',
                    'rgba(239 68 68 / 0.7)',
                    'rgba(245 158 11 / 0.7)',
                    'rgba(249 115 22 / 0.7)',
                  ],
                  borderWidth: 1,
                },
              ],
            }}
            options={{
              ...chartCommon,
              scales: undefined,
            }}
          />
        </div>
      </Panel>

      <Panel title="Threat Timeline" subtitle="Events per minute (last 15m)">
        <div className="h-[260px]">
          <Line
            data={{
              labels: timeline.labels,
              datasets: [
                {
                  label: 'Threats',
                  data: timeline.values,
                  borderColor: COLORS.cyan,
                  backgroundColor: 'rgba(34 211 238 / 0.10)',
                  pointBackgroundColor: COLORS.cyan,
                  tension: 0.35,
                  fill: true,
                },
              ],
            }}
            options={{
              ...chartCommon,
              plugins: {
                ...chartCommon.plugins,
                legend: { display: false },
              },
            }}
          />
        </div>
      </Panel>

      <Panel title="Top Attacking IPs" subtitle="Most frequent sources (sample)">
        <div className="h-[260px]">
          <Bar
            data={{
              labels: top.map((t) => t.ip),
              datasets: [
                {
                  label: 'Events',
                  data: top.map((t) => t.count),
                  backgroundColor: 'rgba(59 130 246 / 0.35)',
                  borderColor: 'rgba(59 130 246 / 0.7)',
                  borderWidth: 1,
                  borderRadius: 8,
                },
              ],
            }}
            options={{
              ...chartCommon,
              plugins: {
                ...chartCommon.plugins,
                legend: { display: false },
              },
            }}
          />
        </div>
      </Panel>

      <Panel title="Severity Distribution" subtitle="LOW → CRITICAL">
        <div className="h-[260px]">
          <Doughnut
            data={{
              labels: severityLabels,
              datasets: [
                {
                  data: severityValues,
                  backgroundColor: [
                    'rgba(52 211 153 / 0.35)',
                    'rgba(245 158 11 / 0.35)',
                    'rgba(249 115 22 / 0.35)',
                    'rgba(239 68 68 / 0.35)',
                  ],
                  borderColor: [
                    'rgba(52 211 153 / 0.7)',
                    'rgba(245 158 11 / 0.7)',
                    'rgba(249 115 22 / 0.7)',
                    'rgba(239 68 68 / 0.7)',
                  ],
                  borderWidth: 1,
                },
              ],
            }}
            options={{
              ...chartCommon,
              scales: undefined,
              cutout: '62%',
            }}
          />
        </div>
      </Panel>
    </div>
  )
}
