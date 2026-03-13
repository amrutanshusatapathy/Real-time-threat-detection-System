import type { ReactNode } from 'react'

export function Panel(props: {
  title: string
  subtitle?: string
  right?: ReactNode
  children: ReactNode
  className?: string
}): ReactNode {
  const { title, subtitle, right, children, className } = props

  return (
    <section className={`panel-surface p-4 animate-fade-up ${className ?? ''}`.trim()}>
      <header className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-slate-200">
            {title}
          </h2>
          {subtitle ? (
            <p className="mt-1 text-xs text-slate-400">{subtitle}</p>
          ) : null}
        </div>
        {right ? <div className="shrink-0">{right}</div> : null}
      </header>

      <div className="mt-4">{children}</div>
    </section>
  )
}
