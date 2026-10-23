/**
 * Parse API timestamps consistently. The backend currently serializes some
 * UTC datetimes without a timezone suffix, so treat timezone-less values as
 * UTC instead of letting JavaScript interpret them in the browser's timezone.
 */
export function parseTimestamp(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value
  if (typeof value === 'number') {
    const milliseconds = Math.abs(value) < 1e12 ? value * 1000 : value
    const date = new Date(milliseconds)
    return Number.isNaN(date.getTime()) ? null : date
  }
  if (typeof value !== 'string' || !value.trim()) return null

  let normalized = value.trim()
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(normalized)
  if (!hasTimezone) {
    normalized = normalized.replace(/^(\d{4}-\d{2}-\d{2})\s+/, '$1T')
    normalized += 'Z'
  }

  const date = new Date(normalized)
  return Number.isNaN(date.getTime()) ? null : date
}

export function timestampValue(value) {
  return parseTimestamp(value)?.getTime() ?? Number.NaN
}

export function timestampIso(value) {
  return parseTimestamp(value)?.toISOString() ?? ''
}

export function formatTimestamp(value, options = {}) {
  const date = parseTimestamp(value)
  if (!date) return '—'
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: 'numeric', minute: '2-digit',
    ...options,
  }).format(date)
}

export function formatDate(value, options = {}) {
  const date = parseTimestamp(value)
  if (!date) return '—'
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    ...options,
  }).format(date)
}
