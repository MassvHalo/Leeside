// The console JSON API, one level under this page: same origin,
// same session cookie, no tokens. 401 means the session died.

export function prefix() {
  return window.location.pathname.replace(/\/$/, '') || '/windside'
}

async function call(path, { method = 'GET', body = null } = {}) {
  const res = await fetch(`${prefix()}/api/v1${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : null,
  })
  if (res.status === 401) {
    window.location.assign(`${prefix()}/login?next=${encodeURIComponent(prefix() + '/')}`)
    throw new Error('logged out')
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = new Error(data.error || `request failed: ${res.status}`)
    err.status = res.status
    throw err
  }
  return data
}

export const getSummary = (window) => call(`/summary?window=${window}`)
export const getEpisodes = (window) => call(`/episodes?window=${window}`)
export const getTraffic = (window, bucket) => call(`/traffic?window=${window}&bucket=${bucket}`)
export const postDecision = (id, decision, window_end_ts) =>
  call(`/episodes/${id}/decision`, { method: 'POST', body: { decision, window_end_ts } })
export const getReview = (window) => call(`/review?window=${window}`)
export const getReviewItem = (scope, id) => call(`/review/${scope}/${encodeURIComponent(id)}`)
export const postReviewDecision = (scope, id, decision, window_end_ts) =>
  call(`/review/${scope}/${encodeURIComponent(id)}/decision`, {
    method: 'POST',
    body: { decision, window_end_ts },
  })
export const getActor = (id) => call(`/actors/${encodeURIComponent(id)}`)
export const getActorTurns = (id, filter = {}) => {
  const p = new URLSearchParams({ limit: '20' })
  if (filter.flag) p.set('flag', filter.flag)
  if (filter.status) p.set('status', filter.status)
  if (filter.route) p.set('route', filter.route)
  return call(`/actors/${encodeURIComponent(id)}/turns?${p}`)
}
export const postActorBlock = (id, action) =>
  call(`/actors/${encodeURIComponent(id)}/block`, { method: 'POST', body: { action } })
export const getStatus = () => call('/status')
