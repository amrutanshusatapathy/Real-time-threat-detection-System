import type { ReactNode } from 'react'
import type { ThreatEvent } from '../types'
import { formatTime } from '../lib/format'
import { Panel } from './Panel'
import { SeverityPill } from './SeverityPill'

function AlertCard(props: { threat: ThreatEvent }): ReactNode {
  const { threat } = props

  return (
    <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-slate-100">
            {threat.type}
          </p>
          <p className="mt-1 truncate text-xs text-slate-300">
            {threat.srcIp} → {threat.target}
          </p>
          <p className="mt-1 text-[11px] text-slate-400 tabular-nums">
            {formatTime(threat.ts)} • {threat.geo.city}, {threat.geo.country}
          </p>
        </div>
        <SeverityPill severity={threat.severity} />
      </div>

      <div className="mt-2 flex flex-wrap gap-2">
        {threat.blocked ? (
          <span className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
            Response: IP blocked
          </span>
        ) : (
          <span className="rounded-md border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
            Action: Investigate
          </span>
        )}
        {typeof threat.anomalyScore === 'number' ? (
          <span className="rounded-md border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-semibold text-cyan-200">
            Anomaly score {threat.anomalyScore.toFixed(2)}
          </span>
        ) : null}
      </div>
    </div>
  )
}

export function AlertsPanel(props: { alerts: ThreatEvent[] }): ReactNode {
  const { alerts } = props

  return (
    <Panel title="High Severity Alerts" subtitle="Immediate attention required">
      <div className="space-y-3">
        {alerts.length === 0 ? (
          <div className="rounded-lg border border-cyan-500/10 bg-slate-950/30 p-4 text-sm text-slate-400">
            No HIGH/CRITICAL alerts in the current window.
          </div>
        ) : (
          alerts.slice(0, 6).map((t) => <AlertCard key={t.id} threat={t} />)
        )}
      </div>
    </Panel>
  )
}
