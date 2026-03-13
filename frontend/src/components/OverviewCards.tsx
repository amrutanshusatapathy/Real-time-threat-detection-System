import type { ReactNode } from 'react'
import type { OverviewStats } from '../types'
import { formatCompactNumber } from '../lib/format'

function Card(props: {
  label: string
  value: string
  accentClassName: string
  helper?: string
}): ReactNode {
  const { label, value, accentClassName, helper } = props

  return (
    <div className="panel-surface p-4 animate-fade-up">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium tracking-wide text-slate-400">
          {label}
        </p>
        <span className={`h-2 w-2 rounded-full ${accentClassName}`} />
      </div>
      <p className="mt-3 text-2xl font-semibold text-slate-100 tabular-nums">
        {value}
      </p>
      {helper ? <p className="mt-1 text-xs text-slate-500">{helper}</p> : null}
    </div>
  )
}

export function OverviewCards(props: { overview: OverviewStats }): ReactNode {
  const { overview } = props

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card
        label="Total Threats Detected"
        value={formatCompactNumber(overview.totalThreats)}
        accentClassName="bg-cyan-400 ring-4 ring-cyan-500/10"
        helper="Cumulative events flagged"
      />
      <Card
        label="Blocked IPs"
        value={formatCompactNumber(overview.blockedIps)}
        accentClassName="bg-emerald-400 ring-4 ring-emerald-500/10"
        helper="Unique sources blocked"
      />
      <Card
        label="Anomaly Detection Alerts"
        value={formatCompactNumber(overview.anomalyAlerts)}
        accentClassName="bg-amber-400 ring-4 ring-amber-500/10"
        helper="ML score ≥ 0.85"
      />
      <Card
        label="Active Network Connections"
        value={formatCompactNumber(overview.activeConnections)}
        accentClassName="bg-blue-400 ring-4 ring-blue-500/10"
        helper="Estimated live sessions"
      />
    </div>
  )
}
