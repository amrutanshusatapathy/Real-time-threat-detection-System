import type { ReactNode } from 'react'

export function TopBar(): ReactNode {
  return (
    <header className="flex flex-col gap-4 border-b border-cyan-500/10 bg-slate-950/40 px-6 py-5 backdrop-blur md:flex-row md:items-center md:justify-between">
      <div>
        <p className="text-xs font-semibold tracking-[0.2em] text-cyan-300/80">
          SECURITY OPERATIONS
        </p>
        <h1 className="mt-2 text-xl font-semibold tracking-tight text-slate-100 sm:text-2xl">
          Real-Time Threat Detection System
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Live monitoring • Rules + anomaly signals • Global visibility
        </p>
      </div>

      <div className="flex items-center gap-3">
        <div className="rounded-xl border border-cyan-500/15 bg-slate-950/50 px-4 py-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse-soft" />
            Stream status
          </div>
          <p className="mt-1 text-sm font-semibold text-cyan-200">ONLINE</p>
        </div>

        <div className="hidden rounded-xl border border-cyan-500/15 bg-slate-950/50 px-4 py-2 sm:block">
          <p className="text-xs font-semibold text-slate-200">Environment</p>
          <p className="mt-1 text-sm font-semibold text-slate-100">SOC Dashboard</p>
        </div>
      </div>
    </header>
  )
}
