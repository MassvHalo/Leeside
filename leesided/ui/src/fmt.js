// Display formatting. Times are the viewer's local clock.

const group = new Intl.NumberFormat('en-US')

export const fmtInt = (n) => group.format(n)

export function fmtClock(ts) {
  const d = new Date(ts * 1000)
  const h = String(d.getHours()).padStart(2, '0')
  const m = String(d.getMinutes()).padStart(2, '0')
  return `${h}:${m}`
}

export function fmtTime(ts) {
  const d = new Date(ts * 1000)
  const h = String(d.getHours()).padStart(2, '0')
  const m = String(d.getMinutes()).padStart(2, '0')
  const s = String(d.getSeconds()).padStart(2, '0')
  return `${h}:${m}:${s}`
}

export function fmtMillis(tsUs) {
  const d = new Date(Math.floor(tsUs / 1000))
  const h = String(d.getHours()).padStart(2, '0')
  const m = String(d.getMinutes()).padStart(2, '0')
  const s = String(d.getSeconds()).padStart(2, '0')
  const ms = String(Math.floor(tsUs / 1000) % 1000).padStart(3, '0')
  return `${h}:${m}:${s}.${ms}`
}

export const fmtConf = (n) => Number(n).toFixed(2)

export function fmtDur(s) {
  const t = Math.max(0, Math.floor(s))
  const h = Math.floor(t / 3600)
  const m = Math.floor((t % 3600) / 60)
  const sec = t % 60
  if (h > 0) return m > 0 ? `${h} h ${m} min` : `${h} h`
  if (m > 0) return sec > 0 ? `${m} min ${sec} s` : `${m} min`
  return `${sec} s`
}

export function fmtMs(ms) {
  if (ms >= 1000) return `${Math.round(ms / 100) / 10} s`
  return `${Math.round(ms)} ms`
}

export function verdictWord(verdict) {
  if (verdict === 'blocked') return 'block'
  if (verdict === 'observed') return 'watch'
  return 'allow'
}

// "08:00 to now", "Through the day", "HH:MM to HH:MM", or one
// clock time when the whole span falls inside a minute. Half the
// window and up reads as the day; clock pairs past midnight would
// otherwise run backwards.
export function fmtSpan(start, end, nowS, windowS) {
  if (end - start >= windowS * 0.5) return 'Through the day'
  if (end - start < 60) return fmtClock(start)
  const tail = end >= nowS - 300 ? 'now' : fmtClock(end)
  return `${fmtClock(start)} to ${tail}`
}
