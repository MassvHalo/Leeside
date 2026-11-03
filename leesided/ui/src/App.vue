<template>
  <div class="frame">
    <header class="topbar">
      <a class="brand" href="#"><svg class="brand-mark" width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><rect class="brand-mark-dim" x="2" y="4" width="10" height="2.4" rx="1"></rect><rect class="brand-mark-hostile" x="6" y="8.8" width="12" height="2.4" rx="1"></rect><rect class="brand-mark-dim" x="4" y="13.6" width="6" height="2.4" rx="1"></rect></svg><span>windside</span></a>
      <button type="button" class="user" aria-haspopup="menu"><span class="user-avatar" aria-hidden="true">{{ roleInitial }}</span><span class="user-text"><span class="user-name" data-field="user.name">{{ role }}</span></span><svg class="chevron" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 L5 6.5 L8 3.5"></path></svg></button>
    </header>
    <aside class="sidebar" aria-label="Console">
      <label class="jump"><input ref="jumpInput" v-model="jump" type="text" placeholder="Jump to actor id" aria-label="Jump to an actor by id prefix" @keydown.enter="doJump"><kbd>/</kbd></label>
      <nav class="nav" aria-label="Sections">
        <a class="nav-link is-current" href="#" aria-current="page"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M2 6.6 L7 2.4 L12 6.6 V12 H8.6 V8.8 H5.4 V12 H2 Z" fill="none"></path></svg><span class="nav-label">Dashboard</span></a>
        <div class="nav-section">Daily</div>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><rect x="1.8" y="1.8" width="10.4" height="10.4" rx="2.4" fill="none"></rect><path d="M4.4 7.2 L6.3 9.1 L9.8 5.2" fill="none"></path></svg><span class="nav-label">Review</span><span v-if="pending > 0" class="count-pill" data-field="review.pending">{{ pending }}</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" href="#">Queue</a><a class="nav-link nav-child" href="#">Decided</a></details>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M1 7 H3.6 L5.2 3 L8 11 L9.8 7 H13" fill="none"></path></svg><span class="nav-label">Traffic</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" href="#">Actors</a><a class="nav-link nav-child" href="#">Clusters</a><a class="nav-link nav-child" href="#">Live</a></details>
        <div class="nav-section">Control</div>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M7 1.2 L12 3 V7 C12 10 9.8 11.9 7 12.8 C4.2 11.9 2 10 2 7 V3 Z" fill="none"></path></svg><span class="nav-label">Protection</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" href="#">Rules</a><a class="nav-link nav-child" href="#">Drafts</a><a class="nav-link nav-child" href="#">Decisions</a><a class="nav-link nav-child" href="#">Mode</a></details>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><circle cx="7" cy="7" r="5.2" fill="none"></circle><circle cx="7" cy="7" r="2.2" fill="none"></circle></svg><span class="nav-label">Intelligence</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" href="#">Model</a><a class="nav-link nav-child" href="#">Assistant</a><a class="nav-link nav-child" href="#">Evals</a><a class="nav-link nav-child" href="#">Fingerprints</a></details>
        <div class="nav-section">System</div>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M1.5 4 H12.5 M1.5 10 H12.5" fill="none"></path><circle cx="5" cy="4" r="1.6" fill="#0A0D12"></circle><circle cx="9.5" cy="10" r="1.6" fill="#0A0D12"></circle></svg><span class="nav-label">Settings</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" href="#">App</a><a class="nav-link nav-child" href="#">Surfaces</a><a class="nav-link nav-child" href="#">Redaction</a><a class="nav-link nav-child" href="#">Assistant</a><a class="nav-link nav-child" href="#">GeoIP</a><a class="nav-link nav-child" href="#">Access</a></details>
      </nav>
      <div class="sidebar-foot">
        <button type="button" class="app-switch" aria-haspopup="menu"><span data-field="app.host">{{ host }}</span><svg class="chevron" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 L5 6.5 L8 3.5"></path></svg></button>
        <span v-if="disconnected" class="connection is-disconnected"><span>Not connected</span></span>
        <span v-else class="connection"><span>Connected, <span data-field="summary.mode">{{ mode }}</span></span></span>
      </div>
    </aside>
    <main class="content">
      <div v-if="disconnected" class="banner" role="status">Can't reach leesided. <template v-if="lastSeen !== null">This is what it last reported at <time class="time" data-field="app.last_seen">{{ fmtClock(lastSeen) }}</time>. </template>Retrying.</div>
      <div :class="disconnected ? 'content-dimmed' : ''">
      <div class="hero">
        <header class="hero-text">
          <p class="crumb">Windside <span aria-hidden="true">&rsaquo;</span> <b>Dashboard</b></p>
          <h1 v-if="!summary" class="headline"></h1>
          <h1 v-else-if="summary.attacks === 0" class="headline">Watching.</h1>
          <h1 v-else class="headline"><span class="headline-dim"><span data-field="summary.attacks">{{ fmtInt(summary.attacks) }}</span> attacks in <span data-field="summary.window">{{ summary.window }}</span>.</span> <span class="headline-rest"><span data-field="summary.stopped">{{ fmtInt(summary.stopped) }}</span> {{ stoppedWord }}.</span><span v-if="showTail" class="headline-tail">In shadow, Windside would have stopped <span data-field="summary.would_have_stopped">{{ fmtInt(summary.would_have_stopped) }}</span> more.</span></h1>
          <div v-if="summary" class="subline-row"><span class="mode-chip" :data-mode="summary.mode"><span data-field="summary.mode">{{ summary.mode }}</span> mode</span><p v-if="summary.attacks === 0" class="subline"><span data-field="summary.requests">{{ fmtInt(summary.requests) }}</span> requests seen<template v-if="summary.fingerprinted !== null">, <span data-field="summary.fingerprinted">{{ summary.fingerprinted }}%</span> fingerprinted</template>, nothing hostile yet</p><p v-else class="subline"><span data-field="summary.waiting">{{ fmtInt(summary.waiting) }}</span> waiting on you.</p></div>
          <div v-if="summary && summary.attacks > 0" class="cta-row"><a v-if="summary.waiting > 0" class="cta cta-primary" :href="`${consolePrefix}/ui/review`">Review what's waiting</a><a class="cta cta-ghost" :href="`${consolePrefix}/ui/traffic`">See all traffic</a></div>
        </header>
        <div class="hero-card">
          <div class="hero-card-head"><span class="card-label">Traffic</span><div class="window-toggle" role="group" aria-label="Time window"><button v-for="w in windows" :key="w" type="button" :data-window="w" :aria-pressed="String(win === w)" @click="setWindow(w)">{{ windowLabel(w) }}</button></div></div>
          <p class="hero-figure"><b data-field="traffic.window_total">{{ traffic ? fmtInt(traffic.window_total) : '' }}</b> requests</p>
          <section class="traffic" aria-label="Traffic over the window">
            <div class="histogram" :style="`--bucket-scale:${bucketScale}`">
              <div v-for="(b, i) in buckets" :key="b.start" class="bucket" :title="`${fmtClock(b.start)}: ${fmtInt(b.total)} requests, ${fmtInt(b.hostile)} hostile`"><div class="bucket-markers"><span v-for="m in markers[i]" :key="m.id" class="glyph marker" data-field="episode.state" :data-state="m.state" :title="m.title" :aria-current="m.selected ? 'true' : null">{{ m.state }}</span></div><div class="bucket-track"><div class="bucket-bar" :style="`--bucket-total:${b.total};--bucket-hostile:${b.hostile}`"><div class="bar-hostile"></div><div class="bar-rest"></div></div></div><time class="bucket-time" data-field="traffic.bucket">{{ fmtClock(b.start) }}</time><span data-field="traffic.total" hidden>{{ b.total }}</span><span data-field="traffic.hostile" hidden>{{ b.hostile }}</span></div>
            </div>
            <div class="traffic-foot">
              <div class="marker-legend" aria-label="Marker legend">
                <span class="legend-item"><span class="glyph" data-state="stopped">stopped</span>Stopped</span>
                <span class="legend-item"><span class="glyph" data-state="waiting">waiting</span>Waiting on you</span>
                <span class="legend-item"><span class="glyph" data-state="watched">watched</span>Watched</span>
              </div>
              <div class="traffic-key"><span class="key-swatch key-swatch-total"></span>All traffic<span class="key-swatch key-swatch-hostile"></span>Hostile</div>
            </div>
          </section>
        </div>
      </div>
      <EpisodePanel
        :episodes="episodes"
        :selected-id="selectedId"
        :done="done"
        :can-decide="canDecide"
        :now-s="nowS"
        :window-s="windowSeconds"
        @select="select"
        @next="next"
        @decide="decide"
      />
      <section v-if="summary" class="tiles" aria-label="Go deeper">
        <a class="tile" :href="`${consolePrefix}/ui/actors`"><span class="tile-label">Who is on your app</span><span class="tile-line"><span data-field="tiles.actors.normal">{{ fmtInt(summary.tiles.actors.normal) }}</span><span class="tile-of">/ <span data-field="tiles.actors.total">{{ fmtInt(summary.tiles.actors.total) }}</span></span></span><span class="tile-bar" aria-hidden="true"><span class="tile-bar-fill" :style="`--share:${share(summary.tiles.actors.normal, summary.tiles.actors.total)}`"></span></span><span class="tile-caption">actors look normal</span><span class="tile-more">See who they are<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></span></a>
        <a class="tile" :href="`${consolePrefix}/ui/rules`"><span class="tile-label">How your rules are doing</span><span class="tile-line"><span data-field="tiles.rules.active">{{ fmtInt(summary.tiles.rules.active) }}</span><span class="tile-of">active</span></span><span class="tile-bar" aria-hidden="true"><span class="tile-bar-fill" :style="`--share:${share(summary.tiles.rules.active, summary.tiles.rules.active + summary.tiles.rules.ready)}`"></span></span><span class="tile-caption"><span data-field="tiles.rules.ready">{{ fmtInt(summary.tiles.rules.ready) }}</span> ready to turn on</span><span class="tile-more">See your rules<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></span></a>
        <a class="tile" :href="`${consolePrefix}/ui/model`"><span class="tile-label">Can you trust the detection</span><span class="tile-line"><span data-field="tiles.reviews.agreed">{{ fmtInt(summary.tiles.reviews.agreed) }}</span><span class="tile-of">/ <span data-field="tiles.reviews.total">{{ fmtInt(summary.tiles.reviews.total) }}</span></span></span><span class="tile-bar" aria-hidden="true"><span class="tile-bar-fill" :style="`--share:${share(summary.tiles.reviews.agreed, summary.tiles.reviews.total)}`"></span></span><span class="tile-caption">agreed with the proposal</span><span class="tile-more">See how it decides<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></span></a>
      </section>
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import EpisodePanel from './EpisodePanel.vue'
import { fmtClock, fmtInt } from './fmt.js'
import { getEpisodes, getSummary, getTraffic, postDecision, prefix } from './api.js'

const windows = ['24h', '7d', '30d']
const bucketsFor = { '24h': '1h', '7d': '12h', '30d': '1d' }
const secondsFor = { '24h': 86400, '7d': 604800, '30d': 2592000 }

const consolePrefix = prefix()
const host = window.location.hostname

const win = ref('24h')
const summary = ref(null)
const episodes = ref([])
const traffic = ref(null)
const selectedId = ref(null)
const done = ref(new Set())
const disconnected = ref(false)
const everLoaded = ref(false)
const lastSeen = ref(null)
const nowS = ref(Math.floor(Date.now() / 1000))
const jump = ref('')
const jumpInput = ref(null)
let retryTimer = null

const windowSeconds = computed(() => secondsFor[win.value])
const buckets = computed(() => (traffic.value ? traffic.value.buckets : []))
const bucketScale = computed(() => {
  const max = buckets.value.reduce((m, b) => Math.max(m, b.total), 0)
  return Math.max(1, max)
})
const role = computed(() => (summary.value ? summary.value.role : ''))
const roleInitial = computed(() => (role.value ? role.value[0].toUpperCase() : ''))
const mode = computed(() => (summary.value ? summary.value.mode : ''))
const pending = computed(() => (summary.value ? summary.value.pending : 0))
const stoppedWord = computed(() => (summary.value && summary.value.mode === 'shadow' ? 'stopped by rules' : 'stopped'))
const showTail = computed(
  () => summary.value !== null && summary.value.mode === 'shadow' && summary.value.would_have_stopped > 0,
)
const canDecide = computed(() => role.value === 'admin' && !disconnected.value)

// List order: stopped, then waiting, then watched; API order inside.
const ordered = computed(() => {
  const by = { stopped: [], waiting: [], watched: [] }
  for (const e of episodes.value) (by[e.state] || by.watched).push(e)
  return [...by.stopped, ...by.waiting, ...by.watched]
})

// Markers sit on the bucket holding each episode's latest activity.
const markers = computed(() => {
  const out = buckets.value.map(() => [])
  for (const e of episodes.value) {
    let at = 0
    buckets.value.forEach((b, i) => {
      if (b.start <= e.span_end) at = i
    })
    out[at].push({ id: e.id, state: e.state, title: e.title, selected: e.id === selectedId.value })
  }
  return out
})

function windowLabel(w) {
  return { '24h': '24 h', '7d': '7 d', '30d': '30 d' }[w]
}

function share(part, total) {
  return total > 0 ? (part / total).toFixed(3) : '0.000'
}

async function load() {
  const w = win.value
  const [s, e, t] = await Promise.all([
    getSummary(w),
    getEpisodes(w),
    getTraffic(w, bucketsFor[w]),
  ])
  summary.value = s
  episodes.value = e
  traffic.value = t
  nowS.value = Math.floor(Date.now() / 1000)
  disconnected.value = false
  everLoaded.value = true
  lastSeen.value = nowS.value
  stopRetry()
  if (!e.some((x) => x.id === selectedId.value)) {
    selectedId.value = ordered.value.length > 0 ? ordered.value[0].id : null
  }
}

function onDown() {
  if (disconnected.value) return
  disconnected.value = true
  if (!retryTimer) retryTimer = setInterval(() => void reload(), 15000)
}

function stopRetry() {
  if (retryTimer) {
    clearInterval(retryTimer)
    retryTimer = null
  }
}

async function reload() {
  try {
    await load()
  } catch (err) {
    if (err && err.message === 'logged out') return
    onDown()
  }
}

async function setWindow(w) {
  if (disconnected.value || w === win.value) return
  win.value = w
  selectedId.value = null
  await reload()
}

function select(id) {
  if (disconnected.value) return
  selectedId.value = id
}

function next(dir) {
  if (disconnected.value || ordered.value.length === 0) return
  const step = dir === -1 ? -1 : 1
  const i = ordered.value.findIndex((e) => e.id === selectedId.value)
  const at = i < 0 ? 0 : (i + step + ordered.value.length) % ordered.value.length
  selectedId.value = ordered.value[at].id
}

async function decide(action) {
  const ep = episodes.value.find((e) => e.id === selectedId.value)
  if (!ep || ep.state !== 'waiting' || !canDecide.value || ep.window_end_ts === null) return
  try {
    await postDecision(ep.id, action, ep.window_end_ts)
    done.value.add(ep.id)
    next(1)
  } catch (err) {
    if (err && err.message === 'logged out') return
    if (err && err.status === 409) {
      await reload()
      return
    }
    onDown()
  }
}

function doJump() {
  const id = jump.value.trim()
  if (id) window.location.assign(`${consolePrefix}/ui/actors/${encodeURIComponent(id)}`)
}

function onKey(ev) {
  const tag = (ev.target && ev.target.tagName) || ''
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || ev.target.isContentEditable) return
  if (ev.key === '/') {
    ev.preventDefault()
    if (jumpInput.value) jumpInput.value.focus()
    return
  }
  if (disconnected.value) return
  if (ev.key === 'j') next(1)
  else if (ev.key === 'k') next(-1)
  else if (ev.key === '1') void decide('confirm')
  else if (ev.key === '2') void decide('benign')
  else if (ev.key === '3') void decide('unknown')
}

onMounted(() => {
  window.addEventListener('keydown', onKey)
  void reload()
})

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey)
  stopRetry()
})
</script>
