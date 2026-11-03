// Display formatting. Times are the viewer's local clock.

const group = new Intl.NumberFormat('en-US')

export const fmtInt = (n) => group.format(n)

export function fmtClock(ts) {
  const d = new Date(ts * 1000)
  const h = String(d.getHours()).padStart(2, '0')
  const m = String(d.getMinutes()).padStart(2, '0')
  return `${h}:${m}`
}

// "08:00 to now", "Through the day", "HH:MM to HH:MM", or one
// clock time when the whole span falls inside a minute.
export function fmtSpan(start, end, nowS, windowS) {
  if (end - start >= windowS * 0.8) return 'Through the day'
  if (end - start < 60) return fmtClock(start)
  const tail = end >= nowS - 300 ? 'now' : fmtClock(end)
  return `${fmtClock(start)} to ${tail}`
}
