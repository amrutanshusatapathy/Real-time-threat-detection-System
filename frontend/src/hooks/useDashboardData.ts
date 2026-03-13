import type { DashboardSnapshot } from '../types'
import { useDashboardApi } from './useDashboardApi'
import { useDashboardMock } from './useDashboardMock'

// In hackathons, a mock-first dashboard is the fastest path to a reliable demo.
// Flip this at runtime with `VITE_USE_MOCK=false` once your backend endpoints exist.
export function useDashboardData(): DashboardSnapshot {
  const useMock = (import.meta.env.VITE_USE_MOCK ?? 'true') !== 'false'

  if (useMock) return useDashboardMock()

  return useDashboardApi()
}
