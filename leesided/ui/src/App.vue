<template>
  <div class="frame">
    <header class="topbar">
      <a class="brand" href="#/"><svg class="brand-mark" width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><rect class="brand-mark-dim" x="2" y="4" width="10" height="2.4" rx="1"></rect><rect class="brand-mark-hostile" x="6" y="8.8" width="12" height="2.4" rx="1"></rect><rect class="brand-mark-dim" x="4" y="13.6" width="6" height="2.4" rx="1"></rect></svg><span>windside</span></a>
      <button type="button" class="user" aria-haspopup="menu"><span class="user-avatar" aria-hidden="true">{{ roleInitial }}</span><span class="user-text"><span class="user-name" data-field="user.name">{{ role }}</span></span><svg class="chevron" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 L5 6.5 L8 3.5"></path></svg></button>
    </header>
    <aside class="sidebar" aria-label="Console">
      <label class="jump"><input ref="jumpInput" v-model="jump" type="text" placeholder="Jump to actor id" aria-label="Jump to an actor by id prefix" @keydown.enter="doJump"><kbd>/</kbd></label>
      <nav class="nav" aria-label="Sections" @click="navClick">
        <a class="nav-link" :class="{ 'is-current': route.group === 'dashboard' }" href="#/" :aria-current="route.group === 'dashboard' ? 'page' : null"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M2 6.6 L7 2.4 L12 6.6 V12 H8.6 V8.8 H5.4 V12 H2 Z" fill="none"></path></svg><span class="nav-label">Dashboard</span></a>
        <div class="nav-section">Daily</div>
        <details class="nav-group" :open="route.group === 'review' ? true : null"><summary class="nav-link" :class="{ 'is-current': route.group === 'review' }"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><rect x="1.8" y="1.8" width="10.4" height="10.4" rx="2.4" fill="none"></rect><path d="M4.4 7.2 L6.3 9.1 L9.8 5.2" fill="none"></path></svg><span class="nav-label">Review</span><span v-if="pending > 0" class="count-pill" data-field="review.pending">{{ pending }}</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" :class="{ 'is-current': route.name === 'review-queue' }" href="#/review" :aria-current="route.name === 'review-queue' ? 'page' : null">Queue</a><a class="nav-link nav-child" :class="{ 'is-current': route.name === 'review-decided' }" href="#/review/decided" :aria-current="route.name === 'review-decided' ? 'page' : null">Decided</a></details>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M1 7 H3.6 L5.2 3 L8 11 L9.8 7 H13" fill="none"></path></svg><span class="nav-label">Traffic</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" :href="`${consolePrefix}/actors`">Actors</a><a class="nav-link nav-child" :href="`${consolePrefix}/clusters`">Clusters</a></details>
        <div class="nav-section">Control</div>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M7 1.2 L12 3 V7 C12 10 9.8 11.9 7 12.8 C4.2 11.9 2 10 2 7 V3 Z" fill="none"></path></svg><span class="nav-label">Protection</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" :href="`${consolePrefix}/rules`">Rules</a><a class="nav-link nav-child" :href="`${consolePrefix}/labels`">Decisions</a></details>
        <details class="nav-group"><summary class="nav-link"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><circle cx="7" cy="7" r="5.2" fill="none"></circle><circle cx="7" cy="7" r="2.2" fill="none"></circle></svg><span class="nav-label">Intelligence</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" :href="`${consolePrefix}/model`">Model</a><a class="nav-link nav-child" :href="`${consolePrefix}/llm`">Assistant</a><a class="nav-link nav-child" :href="`${consolePrefix}/payloads`">Payloads</a></details>
        <template v-if="role !== 'viewer'"><div class="nav-section">System</div>
        <details class="nav-group" :open="route.group === 'settings' ? true : null"><summary class="nav-link" :class="{ 'is-current': route.group === 'settings' }"><svg class="nav-icon" width="16" height="16" viewBox="0 0 14 14" aria-hidden="true"><path d="M1.5 4 H12.5 M1.5 10 H12.5" fill="none"></path><circle cx="5" cy="4" r="1.6" fill="#0A0D12"></circle><circle cx="9.5" cy="10" r="1.6" fill="#0A0D12"></circle></svg><span class="nav-label">Settings</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></summary><a class="nav-link nav-child" :class="{ 'is-current': route.name === 'settings-status' }" href="#/settings" :aria-current="route.name === 'settings-status' ? 'page' : null">Status</a><a class="nav-link nav-child" :class="{ 'is-current': route.name === 'settings-assistant' }" href="#/settings/assistant" :aria-current="route.name === 'settings-assistant' ? 'page' : null">Assistant</a><a class="nav-link nav-child" :href="`${consolePrefix}/settings`">Controls</a></details></template>
      </nav>
      <div class="sidebar-foot">
        <button type="button" class="app-switch" aria-haspopup="menu"><span data-field="app.host">{{ host }}</span><svg class="chevron" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 L5 6.5 L8 3.5"></path></svg></button>
        <span v-if="disconnected" class="connection is-disconnected"><span>Not connected</span></span>
        <span v-else class="connection"><span>Connected, <span data-field="summary.mode">{{ mode }}</span></span></span>
        <span class="connection attribution"><span>Built with Muse Spark Open</span></span>
      </div>
    </aside>
    <main class="content">
      <div v-if="disconnected" class="banner" role="status">Can't reach leesided. <template v-if="lastSeen !== null">This is what it last reported at <time class="time" data-field="app.last_seen">{{ fmtClock(lastSeen) }}</time>. </template>Retrying.</div>
      <div :class="disconnected ? 'content-dimmed' : ''">
      <template v-if="route.group === 'dashboard'">
      <div class="hero">
        <header class="hero-text">
          <p class="crumb">Windside <span aria-hidden="true">&rsaquo;</span> <b>Dashboard</b></p>
          <h1 v-if="!summary" class="headline"></h1>
          <h1 v-else-if="summary.attacks === 0" class="headline">Watching.</h1>
          <h1 v-else class="headline"><span class="headline-dim"><span data-field="summary.attacks">{{ fmtInt(summary.attacks) }}</span> attacks in <span data-field="summary.window">{{ summary.window }}</span>.</span> <span class="headline-rest"><span data-field="summary.stopped">{{ fmtInt(summary.stopped) }}</span> {{ stoppedWord }}.</span><span v-if="showTail" class="headline-tail">In shadow, Windside would have stopped <span data-field="summary.would_have_stopped">{{ fmtInt(summary.would_have_stopped) }}</span> more.</span></h1>
          <div v-if="summary" class="subline-row"><span class="mode-chip" :data-mode="summary.mode"><span data-field="summary.mode">{{ summary.mode }}</span> mode</span><p v-if="summary.attacks === 0" class="subline"><span data-field="summary.requests">{{ fmtInt(summary.requests) }}</span> requests seen<template v-if="summary.fingerprinted !== null">, <span data-field="summary.fingerprinted">{{ summary.fingerprinted }}%</span> fingerprinted</template>, nothing hostile yet</p><p v-else class="subline"><span data-field="summary.waiting">{{ fmtInt(summary.waiting) }}</span> waiting on you.</p></div>
          <div v-if="summary && summary.attacks > 0" class="cta-row"><a v-if="summary.waiting > 0" class="cta cta-primary" href="#/review">Review what's waiting</a><a class="cta cta-ghost" :href="`${consolePrefix}/actors`">See all traffic</a></div>
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
        <a class="tile" :href="`${consolePrefix}/actors`"><span class="tile-label">Who is on your app</span><span class="tile-line"><span data-field="tiles.actors.normal">{{ fmtInt(summary.tiles.actors.normal) }}</span><span class="tile-of">/ <span data-field="tiles.actors.total">{{ fmtInt(summary.tiles.actors.total) }}</span></span></span><span class="tile-bar" aria-hidden="true"><span class="tile-bar-fill" :style="`--share:${share(summary.tiles.actors.normal, summary.tiles.actors.total)}`"></span></span><span class="tile-caption">actors look normal</span><span class="tile-more">See who they are<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></span></a>
        <a class="tile" :href="`${consolePrefix}/rules`"><span class="tile-label">How your rules are doing</span><span class="tile-line"><span data-field="tiles.rules.active">{{ fmtInt(summary.tiles.rules.active) }}</span><span class="tile-of">active</span></span><span class="tile-bar" aria-hidden="true"><span class="tile-bar-fill" :style="`--share:${share(summary.tiles.rules.active, summary.tiles.rules.active + summary.tiles.rules.ready)}`"></span></span><span class="tile-caption"><span data-field="tiles.rules.ready">{{ fmtInt(summary.tiles.rules.ready) }}</span> ready to turn on</span><span class="tile-more">See your rules<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></span></a>
        <a class="tile" :href="`${consolePrefix}/model`"><span class="tile-label">Can you trust the detection</span><span class="tile-line"><span data-field="tiles.reviews.agreed">{{ fmtInt(summary.tiles.reviews.agreed) }}</span><span class="tile-of">/ <span data-field="tiles.reviews.total">{{ fmtInt(summary.tiles.reviews.total) }}</span></span></span><span class="tile-bar" aria-hidden="true"><span class="tile-bar-fill" :style="`--share:${share(summary.tiles.reviews.agreed, summary.tiles.reviews.total)}`"></span></span><span class="tile-caption">agreed with the proposal</span><span class="tile-more">See how it decides<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></span></a>
      </section>
      </template>
      <ReviewPanel
        v-else-if="route.group === 'review'"
        :queue="review ? review.items : null"
        :queue-total="review ? review.total : 0"
        :queue-disagree="review ? review.disagree : 0"
        :decided="review ? review.decided : emptyDecided"
        :item="reviewItem"
        :item-loading="reviewItemLoading"
        :tab="route.name === 'review-decided' ? 'decided' : 'queue'"
        :selected-key="reviewSelectionKey"
        :can-decide="canDecide"
        :disconnected="disconnected"
        :console-prefix="consolePrefix"
        @select="reviewSelect"
        @next="reviewNext"
        @decide="reviewDecide"
      />
      <StatusPanel
        v-else-if="route.name === 'settings-status'"
        :status="status"
        :assistant-model="summary && summary.assistant ? summary.assistant.model : null"
        :console-prefix="consolePrefix"
      />
      <AssistantPanel
        v-else-if="route.name === 'settings-assistant'"
        :assistant="summary ? summary.assistant : null"
        :is-operator="role !== 'viewer'"
      />
      <ActorPanel
        v-else
        :actor="actor"
        :actor-id="route.actorId || ''"
        :tab="route.name === 'actor-raw' ? 'raw' : 'overview'"
        :not-found="actorNotFound"
        :can-decide="canDecide"
        :disconnected="disconnected"
        :console-prefix="consolePrefix"
        :mode="mode"
        @decide="actorDecide"
        @block="actorBlockOp('block')"
        @unblock="actorBlockOp('unblock')"
      />
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import ActorPanel from './ActorPanel.vue'
import AssistantPanel from './AssistantPanel.vue'
import EpisodePanel from './EpisodePanel.vue'
import ReviewPanel from './ReviewPanel.vue'
import StatusPanel from './StatusPanel.vue'
import { fmtClock, fmtInt } from './fmt.js'
import {
  getActor,
  getEpisodes,
  getReview,
  getReviewItem,
  getStatus,
  getSummary,
  getTraffic,
  postActorBlock,
  postDecision,
  postReviewDecision,
  prefix,
} from './api.js'

// Hash routes: '' or '#/' dashboard, '#/review' queue, '#/review/decided',
// '#/review/{actor|cluster}/{id}' queue with a selected item,
// '#/actors/{id}' and '#/actors/{id}/raw', '#/settings' and
// '#/settings/assistant'.
// Unknown hashes fall back to the dashboard; turn anchors use
// replaceState, never routing.
function parseHash() {
  const h = window.location.hash.replace(/^#/, '')
  if (h === '' || h === '/') return { group: 'dashboard', name: 'dashboard', scope: null, id: null, actorId: null }
  if (h === '/review') return { group: 'review', name: 'review-queue', scope: null, id: null, actorId: null }
  if (h === '/review/decided') return { group: 'review', name: 'review-decided', scope: null, id: null, actorId: null }
  if (h === '/settings/assistant') return { group: 'settings', name: 'settings-assistant', scope: null, id: null, actorId: null }
  if (h === '/settings') return { group: 'settings', name: 'settings-status', scope: null, id: null, actorId: null }
  const m = h.match(/^\/review\/(actor|cluster)\/(.+)$/)
  if (m) return { group: 'review', name: 'review-queue', scope: m[1], id: decodeURIComponent(m[2]), actorId: null }
  const raw = h.match(/^\/actors\/(.+)\/raw$/)
  if (raw) return { group: 'actor', name: 'actor-raw', scope: null, id: null, actorId: decodeURIComponent(raw[1]) }
  const a = h.match(/^\/actors\/(.+)$/)
  if (a) return { group: 'actor', name: 'actor-overview', scope: null, id: null, actorId: decodeURIComponent(a[1]) }
  return { group: 'dashboard', name: 'dashboard', scope: null, id: null, actorId: null }
}

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

const route = ref(parseHash())
const review = ref(null)
const reviewItem = ref(null)
const reviewItemLoading = ref(false)
const emptyDecided = { total: 0, agreed: 0, items: [] }
const actor = ref(null)
const actorNotFound = ref(false)
const status = ref(null)

// Selection is the route's item, else the first queue row. Plain #/review
// shows the first item without rewriting the URL.
const reviewSelection = computed(() => {
  if (route.value.scope && route.value.id) return { scope: route.value.scope, id: route.value.id }
  if (review.value && review.value.items.length > 0) {
    const first = review.value.items[0]
    return { scope: first.scope, id: first.id }
  }
  return null
})
const reviewSelectionKey = computed(() =>
  reviewSelection.value ? `${reviewSelection.value.scope}:${reviewSelection.value.id}` : null,
)

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

async function loadDashboard() {
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

// The Decided tab reads a fixed 7-day window: the design gives the
// Review page no window toggle.
async function loadReview() {
  const [s, r] = await Promise.all([getSummary('24h'), getReview('7d')])
  summary.value = s
  review.value = r
  nowS.value = Math.floor(Date.now() / 1000)
  disconnected.value = false
  everLoaded.value = true
  lastSeen.value = nowS.value
  stopRetry()
  await loadReviewItem()
}

async function loadReviewItem() {
  const sel = reviewSelection.value
  if (!sel) {
    reviewItem.value = null
    reviewItemLoading.value = false
    return
  }
  if (reviewItem.value && reviewItem.value.scope === sel.scope && reviewItem.value.id === sel.id) return
  reviewItemLoading.value = true
  try {
    reviewItem.value = await getReviewItem(sel.scope, sel.id)
  } catch (err) {
    if (err && err.message === 'logged out') return
    // Unknown ids show the empty detail, not the banner.
    if (err && err.status === 404) reviewItem.value = null
    else throw err
  } finally {
    reviewItemLoading.value = false
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

async function loadActor() {
  actorNotFound.value = false
  if (!route.value.actorId) {
    actor.value = null
    return
  }
  const [s, a] = await Promise.all([getSummary('24h'), getActor(route.value.actorId)])
  summary.value = s
  actor.value = a
  nowS.value = Math.floor(Date.now() / 1000)
  disconnected.value = false
  everLoaded.value = true
  lastSeen.value = nowS.value
  stopRetry()
}

async function loadAssistant() {
  summary.value = await getSummary('24h')
  nowS.value = Math.floor(Date.now() / 1000)
  disconnected.value = false
  everLoaded.value = true
  lastSeen.value = nowS.value
  stopRetry()
}

async function loadStatus() {
  const [s, st] = await Promise.all([getSummary('24h'), getStatus()])
  summary.value = s
  status.value = st
  nowS.value = Math.floor(Date.now() / 1000)
  disconnected.value = false
  everLoaded.value = true
  lastSeen.value = nowS.value
  stopRetry()
}

async function reload() {
  try {
    if (route.value.group === 'review') await loadReview()
    else if (route.value.group === 'actor') await loadActor()
    else if (route.value.name === 'settings-status') await loadStatus()
    else if (route.value.name === 'settings-assistant') await loadAssistant()
    else await loadDashboard()
  } catch (err) {
    if (err && err.message === 'logged out') return
    if (route.value.group === 'actor' && err && err.status === 404) {
      actorNotFound.value = true
      actor.value = null
      return
    }
    onDown()
  }
}

function onHashChange() {
  const prev = route.value
  const next = parseHash()
  route.value = next
  if (next.group !== prev.group) {
    void reload()
  } else if (next.group === 'review' && (next.scope !== prev.scope || next.id !== prev.id)) {
    reloadReviewItem()
  } else if (next.group === 'actor' && next.actorId !== prev.actorId) {
    void reload()
  } else if (next.group === 'settings' && next.name !== prev.name) {
    void reload()
  }
}

async function reloadReviewItem() {
  try {
    await loadReviewItem()
  } catch (err) {
    if (err && err.message === 'logged out') return
    onDown()
  }
}

function navClick(ev) {
  // Sections without a page yet stay dead instead of routing home.
  if (ev.target && ev.target.closest && ev.target.closest('a[href="#"]')) ev.preventDefault()
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

function reviewSelect(scope, id) {
  if (disconnected.value) return
  window.location.hash = `#/review/${scope}/${encodeURIComponent(id)}`
}

function reviewNext(dir) {
  if (disconnected.value || !review.value || review.value.items.length === 0) return
  const items = review.value.items
  const step = dir === -1 ? -1 : 1
  const sel = reviewSelection.value
  const i = sel ? items.findIndex((q) => q.scope === sel.scope && q.id === sel.id) : -1
  const at = i < 0 ? 0 : (i + step + items.length) % items.length
  window.location.hash = `#/review/${items[at].scope}/${encodeURIComponent(items[at].id)}`
}

async function reviewDecide(action) {
  const item = reviewItem.value
  if (!item || !canDecide.value || !item.window || item.window.window_end_ts === null) return
  const nextKey = item.queue.next ? `${item.queue.next.scope}:${item.queue.next.id}` : null
  try {
    await postReviewDecision(item.scope, item.id, action, item.window.window_end_ts)
    reviewItem.value = null
    const [s, r] = await Promise.all([getSummary('24h'), getReview('7d')])
    summary.value = s
    review.value = r
    const still = nextKey && r.items.some((q) => `${q.scope}:${q.id}` === nextKey)
    if (still) {
      const [scope, ...rest] = nextKey.split(':')
      window.location.hash = `#/review/${scope}/${encodeURIComponent(rest.join(':'))}`
    } else if (r.items.length > 0) {
      window.location.hash = `#/review/${r.items[0].scope}/${encodeURIComponent(r.items[0].id)}`
    } else {
      window.location.hash = '#/review'
      await loadReviewItem()
    }
  } catch (err) {
    if (err && err.message === 'logged out') return
    if (err && err.status === 409) {
      await reload()
      return
    }
    onDown()
  }
}

async function actorDecide(action) {
  const a = actor.value
  const windowTs = a && a.window ? a.window.window_end_ts : null
  if (!a || !canDecide.value || a.state !== 'waiting' || windowTs === null) return
  try {
    await postReviewDecision('actor', a.id, action, windowTs)
    await reload()
  } catch (err) {
    if (err && err.message === 'logged out') return
    if (err && err.status === 409) {
      await reload()
      return
    }
    onDown()
  }
}

async function actorBlockOp(kind) {
  const a = actor.value
  if (!a || !canDecide.value) return
  try {
    await postActorBlock(a.id, kind)
    await reload()
  } catch (err) {
    if (err && err.message === 'logged out') return
    onDown()
  }
}

function doJump() {
  const id = jump.value.trim()
  if (id) window.location.hash = `#/actors/${encodeURIComponent(id)}`
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
  if (route.value.group === 'review') {
    if (route.value.name !== 'review-queue') return
    if (ev.key === 'j') reviewNext(1)
    else if (ev.key === 'k') reviewNext(-1)
    else if (ev.key === '1') void reviewDecide('confirm')
    else if (ev.key === '2') void reviewDecide('benign')
    else if (ev.key === '3') void reviewDecide('unknown')
    return
  }
  if (route.value.group === 'actor') {
    if (route.value.name !== 'actor-overview') return
    if (ev.key === '1') void actorDecide('confirm')
    else if (ev.key === '2') void actorDecide('benign')
    else if (ev.key === '3') void actorDecide('unknown')
    return
  }
  if (ev.key === 'j') next(1)
  else if (ev.key === 'k') next(-1)
  else if (ev.key === '1') void decide('confirm')
  else if (ev.key === '2') void decide('benign')
  else if (ev.key === '3') void decide('unknown')
}

onMounted(() => {
  window.addEventListener('keydown', onKey)
  window.addEventListener('hashchange', onHashChange)
  void reload()
})

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey)
  window.removeEventListener('hashchange', onHashChange)
  stopRetry()
})
</script>
