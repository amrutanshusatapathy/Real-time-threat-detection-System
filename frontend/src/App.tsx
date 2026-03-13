import type { ReactNode } from 'react'
import { AlertsPanel } from './components/AlertsPanel'
import { GlobalAttackMap } from './components/GlobalAttackMap'
import { LiveThreatFeed } from './components/LiveThreatFeed'
import { NetworkActivityPanel } from './components/NetworkActivityPanel'
import { OverviewCards } from './components/OverviewCards'
import { ThreatCharts } from './components/ThreatCharts'
import { TopBar } from './components/TopBar'
import { useDashboardData } from './hooks/useDashboardData'

export default function App(): ReactNode {
  const snapshot = useDashboardData()

  return (
    <div className="min-h-full bg-gradient-to-b from-slate-950 via-slate-950 to-slate-900 text-slate-100">
      <TopBar />

      <main className="space-y-4 px-6 py-6">
        <OverviewCards overview={snapshot.overview} />

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <div className="space-y-4 xl:col-span-8">
            <ThreatCharts threats={snapshot.threats} />
            <GlobalAttackMap threats={snapshot.threats} />
          </div>

          <div className="space-y-4 xl:col-span-4">
            <LiveThreatFeed threats={snapshot.threats} />
            <NetworkActivityPanel network={snapshot.network} />
            <AlertsPanel alerts={snapshot.highSeverityAlerts} />
          </div>
        </div>
      </main>

      <footer className="px-6 pb-6 text-xs text-slate-500">
        Data source: {(
          <span className="font-semibold text-slate-400">Mock stream</span>
        )}{' '}
        (set <span className="font-mono">VITE_USE_MOCK=false</span> to wire a backend)
      </footer>
    </div>
  )
}
