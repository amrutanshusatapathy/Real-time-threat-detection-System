import { useEffect, useMemo, useRef } from 'react'
import type { ReactNode } from 'react'
import type { ThreatEvent } from '../types'
import { formatTime } from '../lib/format'
import { Panel } from './Panel'
import { SeverityPill } from './SeverityPill'

function FeedRow(props: { threat: ThreatEvent }): ReactNode {
  const { threat } = props

  return (
    <div className="grid grid-cols-[88px_1fr] gap-2 rounded-lg border border-cyan-500/10 bg-slate-950/30 p-3 transition hover:border-cyan-400/20">
      <div className="text-xs text-slate-400 tabular-nums">{formatTime(threat.ts)}</div>
      <div className="min-w-0">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-slate-100">
              {threat.srcIp}
              <span className="ml-2 text-xs font-medium text-slate-400">
                → {threat.target}
              </span>
            </p>
            <p className="mt-1 truncate text-xs text-slate-400">
              {threat.type}
              <span className="mx-2 text-slate-600">•</span>
              {threat.geo.city}, {threat.geo.country}
              {threat.blocked ? (
                <span className="ml-2 rounded-md border border-emerald-500/20 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-300">
                  BLOCKED
                </span>
              ) : null}
              {typeof threat.anomalyScore === 'number' ? (
                <span className="ml-2 rounded-md border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300">
                  ML {threat.anomalyScore.toFixed(2)}
                </span>
              ) : null}
            </p>
          </div>
          <SeverityPill severity={threat.severity} />
        </div>
      </div>
    </div>
  )
}

export function LiveThreatFeed(props: { threats: ThreatEvent[] }): ReactNode {
  const { threats } = props
  const listRef = useRef<HTMLDivElement | null>(null)

  const items = useMemo(() => {
    // Show newest last so we can auto-scroll down
    return threats.slice(-40)
  }, [threats])

  useEffect(() => {
    const el = listRef.current
    if (!el) return
    el.scrollTop = el.scrollHeight
  }, [items.length])

  return (
    <Panel
      title="Live Threat Feed"
      subtitle="Real-time stream of detected activity"
      right={
        <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-1 text-xs font-semibold text-cyan-200">
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse-soft" />
          LIVE
        </span>
      }
    >
      <div
        ref={listRef}
        className="max-h-[420px] space-y-3 overflow-y-auto pr-1"
      >
        {items.map((t) => (
          <FeedRow key={t.id} threat={t} />
        ))}
      </div>
    </Panel>
  )
}
