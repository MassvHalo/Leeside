// Thin client for the leesided API behind nginx at /api. The bearer token
// lives in localStorage; a 401 clears it and sends the user back to login.
import { ref } from 'vue'

const KEY = 'leeside.token'

function readToken() {
  try {
    return localStorage.getItem(KEY) || ''
  } catch {
    return ''
  }
}

export const token = ref(readToken())

export function setToken(t) {
  token.value = t
  try {
    if (t) localStorage.setItem(KEY, t)
    else localStorage.removeItem(KEY)
  } catch {
    // Private windows can refuse storage; the token then lasts the tab.
  }
}

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error || `HTTP ${status}`)
    this.status = status
    this.body = body
  }
}

export async function api(method, path, body) {
  const headers = { Authorization: `Bearer ${token.value}` }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 401) {
    setToken('')
    throw new ApiError(401, { error: 'token rejected' })
  }
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) throw new ApiError(res.status, data)
  return data
}

export const get = (p) => api('GET', p)
export const put = (p, b) => api('PUT', p, b)
export const post = (p, b) => api('POST', p, b)
export const del = (p) => api('DELETE', p)

export function ago(unixS, now = Date.now() / 1000) {
  const d = Math.round(now - unixS)
  if (d < 60) return `${d}s ago`
  if (d < 3600) return `${Math.floor(d / 60)}m ago`
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`
  return `${Math.floor(d / 86400)}d ago`
}

export function left(s) {
  if (s <= 0) return 'expired'
  const m = Math.floor(s / 60)
  const sec = s % 60
  if (m >= 60) return `${Math.floor(m / 60)}h ${m % 60}m`
  return m ? `${m}m ${String(sec).padStart(2, '0')}s` : `${sec}s`
}

export function clock(unixS) {
  return new Date(unixS * 1000).toLocaleTimeString([], { hour12: false })
}
