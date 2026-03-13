import type { ReactNode } from 'react'
import type { Severity } from '../types'

function classesForSeverity(severity: Severity): string {
  switch (severity) {
    case 'LOW':
      return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20'
    case 'MEDIUM':
      return 'bg-amber-500/10 text-amber-300 border-amber-500/20'
    case 'HIGH':
      return 'bg-orange-500/10 text-orange-300 border-orange-500/20'
    case 'CRITICAL':
      return 'bg-red-500/10 text-red-300 border-red-500/25'
    default:
      return 'bg-slate-500/10 text-slate-200 border-slate-500/20'
  }
}

export function SeverityPill(props: { severity: Severity }): ReactNode {
  const { severity } = props
  return (
    <span
      className={
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold tracking-wide ' +
        classesForSeverity(severity)
      }
    >
      {severity}
    </span>
  )
}
