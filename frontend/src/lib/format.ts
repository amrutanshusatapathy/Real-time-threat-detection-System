export function formatTime(isoTs: string): string {
  const date = new Date(isoTs)
  if (Number.isNaN(date.getTime())) return '--:--:--'
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

export function formatDateTime(isoTs: string): string {
  const date = new Date(isoTs)
  if (Number.isNaN(date.getTime())) return '—'
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date)
}

export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}

export function formatCompactNumber(value: number): string {
  return new Intl.NumberFormat(undefined, { notation: 'compact' }).format(value)
}

export function formatMbps(value: number): string {
  return `${value.toFixed(1)} Mbps`
}
