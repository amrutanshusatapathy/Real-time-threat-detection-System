import { useEffect, useMemo, useState } from 'react'
import type { DashboardSnapshot } from '../types'
import { createMockEngine } from '../mock/mockEngine'

export function useDashboardMock(): DashboardSnapshot {
  const engine = useMemo(() => createMockEngine(90), [])
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(() => engine.snapshot())

  useEffect(() => {
    const id = window.setInterval(() => {
      setSnapshot(engine.tick())
    }, 1000)

    return () => window.clearInterval(id)
  }, [engine])

  return snapshot
}
