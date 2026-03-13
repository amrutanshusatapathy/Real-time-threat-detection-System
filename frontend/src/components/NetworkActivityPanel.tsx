import type { ReactNode } from 'react'
import type { NetworkStats } from '../types'
import { clamp, formatCompactNumber, formatMbps } from '../lib/format'
import { Panel } from './Panel'

function Meter(props: {
  label: string
  value: string
  percent: number
  barClassName: string
}): ReactNode {
  const { label, value, percent, barClassName } = props

  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-medium tracking-wide text-slate-400">
          {label}
        </p>
        <p className="text-xs font-semibold text-slate-200 tabular-nums">
          {value}
        </p>
      </div>
      <div className="mt-2 h-2 w-full rounded-full bg-slate-800/60">
        <div
          className={`h-2 rounded-full ${barClassName} transition-all duration-300`}
          style={{ width: `${clamp(percent, 0, 100)}%` }}
        />
      </div>
    </div>
  )
}

export function NetworkActivityPanel(props: { network: NetworkStats }): ReactNode {
  const { network } = props

  // These are just display scales for the demo.
  const ppsPercent = (network.packetsPerSecond / 6000) * 100
  const bwPercent = (network.bandwidthMbps / 950) * 100
  const connPercent = (network.activeConnections / 5000) * 100

  return (
    <Panel title="Network Activity" subtitle="Live transport indicators">
      <div className="space-y-4">
        <Meter
          label="Packets / second"
          value={formatCompactNumber(network.packetsPerSecond)}
          percent={ppsPercent}
          barClassName="bg-cyan-500/60"
        />
        <Meter
          label="Bandwidth usage"
          value={formatMbps(network.bandwidthMbps)}
          percent={bwPercent}
          barClassName="bg-blue-500/60"
        />
        <Meter
          label="Active connections"
          value={formatCompactNumber(network.activeConnections)}
          percent={connPercent}
          barClassName="bg-emerald-500/60"
        />
      </div>
    </Panel>
  )
}
