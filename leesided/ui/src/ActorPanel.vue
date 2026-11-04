<template>
  <header v-if="!actor && !notFound" class="page-head page-head-tabs" aria-busy="true">
    <div class="page-head-text">
      <a class="crumb" :href="`${consolePrefix}/ui/actors`">Traffic <span aria-hidden="true">&rsaquo;</span> <b>Actors</b></a>
      <span class="skeleton skeleton-title"></span>
    </div>
    <nav class="tabs" aria-label="Page sections">
      <a class="tab" :href="`#/actors/${encodeURIComponent(actorId)}`" :aria-current="tab === 'overview' ? 'page' : null">Overview</a>
      <a class="tab" :href="`#/actors/${encodeURIComponent(actorId)}/raw`" :aria-current="tab === 'raw' ? 'page' : null">Raw</a>
    </nav>
  </header>
  <header v-else-if="notFound" class="page-head page-head-tabs">
    <div class="page-head-text">
      <p class="crumb">Traffic <span aria-hidden="true">&rsaquo;</span> <b>Actors</b></p>
      <div class="headline-row"><h1 class="headline">No actor with this id.</h1></div>
      <p class="subline">It may have merged into another actor. Its turns are still under <a class="inline-more" :href="`${consolePrefix}/ui/traffic`">Traffic<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></a></p>
    </div>
  </header>
  <header v-else class="page-head page-head-tabs">
    <div class="page-head-text">
      <a class="crumb" :href="`${consolePrefix}/ui/actors`">Traffic <span aria-hidden="true">&rsaquo;</span> <b>Actors</b></a>
      <div class="headline-row"><h1 class="headline" data-field="actor.headline">{{ actor.headline }}</h1></div>
      <p class="actor-idline"><span data-field="actor.kind">{{ actor.kind }}</span> <span class="actor-id" data-field="actor.id">{{ actor.id }}</span> <button type="button" class="copy" data-copy @click="copyText(actor.id, 'id')">{{ copiedKey === 'id' ? 'Copied' : 'Copy' }}</button></p>
    </div>
    <div v-if="canDecide" class="head-actions">
      <button v-if="actor.blocked" type="button" class="decision" data-action="unblock" data-field="decision.action" :disabled="disconnected" @click="askUnblock">Unblock</button>
      <button v-else type="button" class="decision" data-action="block" data-field="decision.action" :disabled="disconnected" @click="$emit('block')">Block</button>
    </div>
    <nav class="tabs" aria-label="Page sections">
      <a class="tab" :href="`#/actors/${encodeURIComponent(actor.id)}`" :aria-current="tab === 'overview' ? 'page' : null">Overview</a>
      <a class="tab" :href="`#/actors/${encodeURIComponent(actor.id)}/raw`" :aria-current="tab === 'raw' ? 'page' : null">Raw</a>
    </nav>
  </header>

  <div v-if="!actor && !notFound" class="panels">
    <section v-for="n in 4" :key="n" class="panel" aria-busy="true">
      <span class="skeleton skeleton-line skeleton-short"></span>
      <span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line"></span>
    </section>
  </div>

  <template v-else-if="actor && tab === 'raw'">
    <div class="page-sub"><h2 class="headline">Everything stored for this actor. Nothing summarised.</h2></div>
    <div class="panels">
      <section class="panel panel-wide" aria-label="Actors row">
        <h3 class="panel-title">Actors row</h3>
        <div class="table-wrap"><table class="raw-table"><tbody>
          <tr v-for="row in rawActorRows" :key="row.key">
            <th class="raw-key" data-field="raw.column" scope="row">{{ row.key }}</th>
            <td class="raw-value" data-field="raw.value">{{ row.value }}</td>
            <td class="raw-copy"><button type="button" class="copy" data-copy @click="copyText(row.value, `actor:${row.key}`)">{{ copiedKey === `actor:${row.key}` ? 'Copied' : 'Copy' }}</button></td>
          </tr>
        </tbody></table></div>
      </section>
      <section class="panel panel-wide" aria-label="Bindings rows">
        <h3 class="panel-title">Bindings rows</h3>
        <div class="table-wrap"><table class="raw-table"><tbody>
          <template v-for="(b, i) in actor.bindings" :key="`${b.kind}:${b.value}`">
            <tr v-for="row in rawBindingRows(b, i)" :key="row.key">
              <th class="raw-key" data-field="raw.column" scope="row">{{ row.key }}</th>
              <td class="raw-value" data-field="raw.value">{{ row.value }}</td>
              <td class="raw-copy"><button type="button" class="copy" data-copy @click="copyText(row.value, `binding:${row.key}`)">{{ copiedKey === `binding:${row.key}` ? 'Copied' : 'Copy' }}</button></td>
            </tr>
          </template>
        </tbody></table></div>
      </section>
      <section v-if="actor.raw_turn" class="panel panel-wide" aria-label="Latest turns row">
        <h3 class="panel-title">Latest turns row</h3>
        <div class="table-wrap"><table class="raw-table"><tbody>
          <tr v-for="key in rawTurnKeys" :key="key">
            <th class="raw-key" data-field="raw.column" scope="row">{{ key }}</th>
            <td class="raw-value" data-field="raw.value">{{ rawText(actor.raw_turn[key]) }}</td>
            <td class="raw-copy"><button type="button" class="copy" data-copy @click="copyText(rawText(actor.raw_turn[key]), `turn:${key}`)">{{ copiedKey === `turn:${key}` ? 'Copied' : 'Copy' }}</button></td>
          </tr>
        </tbody></table></div>
      </section>
    </div>
  </template>

  <div v-else-if="actor" class="panels">
    <section class="panel" aria-label="Identity">
      <h3 class="panel-title">Identity</h3>
      <p v-if="actor.bindings.length > 0" class="panel-sentence">Recognised by {{ identityArticle }} <span data-field="actor.identity.method">{{ identityMethod }}</span> {{ identityCameBack }}. <span data-field="actor.identity.state">{{ actor.confirmed ? 'Confirmed' : 'Unconfirmed' }}</span>.</p>
      <p v-else class="panel-sentence">Not recognised yet.</p>
      <dl class="facts">
        <div><dt>Surfaces</dt><dd data-field="actor.surfaces">{{ actor.surfaces.join(', ') }}</dd></div>
        <div><dt>Network</dt><dd>&mdash;</dd></div>
        <div><dt>Country</dt><dd>&mdash;</dd></div>
        <div><dt>Cluster</dt><dd v-if="actor.cluster"><a class="time" data-field="actor.cluster" :href="`${consolePrefix}/ui/clusters/${encodeURIComponent(actor.cluster)}`">{{ actor.cluster }}</a></dd><dd v-else>&mdash;</dd></div>
      </dl>
      <div class="table-wrap"><table class="dense-table">
        <thead><tr><th>Binding</th><th>Value</th><th>State</th><th>First</th><th>Last</th></tr></thead>
        <tbody>
          <tr v-for="b in actor.bindings" :key="`${b.kind}:${b.value}`">
            <td data-field="actor.binding.kind">{{ b.kind }}</td>
            <td data-field="actor.binding.value">{{ b.value }}</td>
            <td data-field="actor.binding.state">{{ bindingState(b) }}</td>
            <td><time class="time" data-field="actor.binding.first">{{ fmtTime(Math.floor(b.first_seen / 1000000)) }}</time></td>
            <td><time class="time" data-field="actor.binding.last">{{ fmtTime(Math.floor(b.last_seen / 1000000)) }}</time></td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <section class="panel" aria-label="Client">
      <h3 class="panel-title">Client</h3>
      <p class="panel-sentence">{{ clientSentence }}</p>
      <dl class="facts facts-grid">
        <div><dt>UA family</dt><dd data-field="actor.client.ua_family">{{ actor.client.ua_class || '—' }}</dd></div>
        <div><dt>JA4 class</dt><dd data-field="actor.client.ja4_class" :class="{ 'is-malicious': actor.client.ja4_hostile }">{{ actor.client.ja4_class || '—' }}</dd></div>
        <div><dt>JA4T</dt><dd data-field="actor.client.ja4t">{{ actor.client.ja4t || '—' }}</dd></div>
        <div><dt>Header shape</dt><dd data-field="actor.client.header_shape">{{ shapeLine }}</dd></div>
      </dl>
      <ul v-if="actor.client.flags.length > 0" class="flag-list">
        <li v-for="f in actor.client.flags" :key="f.name" class="flag-row">
          <span data-field="actor.flag.phrase">{{ f.phrase }}</span>
          <a class="count-link" data-field="actor.flag.share" href="#turns" @click.prevent="setFilter({ flag: f.name })">{{ Math.round(f.rate * 100) }}%</a>
        </li>
      </ul>
    </section>

    <section class="panel panel-wide" aria-label="Activity">
      <h3 class="panel-title">Activity</h3>
      <p class="panel-sentence"><a class="count-link" data-field="actor.turns" href="#turns" @click.prevent="clearFilter">{{ fmtInt(actor.activity.turns) }}</a> turns over <a class="count-link" data-field="actor.activity.active" href="#turns" @click.prevent="clearFilter">{{ fmtDur(actor.activity.active_s) }}</a>{{ activityTail }}.</p>
      <div class="histogram" :style="`--bucket-scale:${histogramScale}`">
        <div v-for="b in actor.histogram" :key="b.at" class="bucket" :title="`${fmtClock(b.at)}: ${fmtInt(b.total)} turns, ${fmtInt(b.hostile)} hostile`">
          <div class="bucket-markers"><span v-if="inBucket(b.at)" class="marker-glyph" :title="`Blocked at ${fmtClock(actor.marker_at)}`">⛔</span></div>
          <div class="bucket-track"><div class="bucket-bar" :style="`--bucket-total:${b.total};--bucket-hostile:${b.hostile}`"><div class="bar-hostile"></div><div class="bar-rest"></div></div></div>
          <time class="bucket-time" data-field="traffic.bucket">{{ fmtClock(b.at) }}</time>
          <span data-field="traffic.total" hidden>{{ b.total }}</span><span data-field="traffic.hostile" hidden>{{ b.hostile }}</span>
        </div>
      </div>
      <div class="activity-grid">
        <div>
          <ul class="count-list">
            <li><span data-field="actor.status.404">404</span> <a class="count-link" href="#turns" @click.prevent="setFilter({ status: '404' })">{{ fmtInt(actor.activity.not_found) }}</a></li>
            <li><span data-field="actor.status.2xx">2xx</span> <a class="count-link" href="#turns" @click.prevent="setFilter({ status: '2xx' })">{{ fmtInt(actor.activity.ok_2xx) }}</a></li>
            <li><span data-field="actor.status.403">403, blocked</span> <a class="count-link" href="#turns" @click.prevent="setFilter({ status: '403' })">{{ fmtInt(actor.activity.denied) }}</a></li>
          </ul>
          <div class="status-bar" aria-hidden="true">
            <span class="status-seg status-seg-hostile" :style="`--status-share:${statusShares.hostile}`"></span>
            <span class="status-seg status-seg-ok" :style="`--status-share:${statusShares.ok}`"></span>
            <span class="status-seg status-seg-blocked" :style="`--status-share:${statusShares.blocked}`"></span>
          </div>
        </div>
        <div>
          <ul v-if="actor.top_routes.length > 0" class="count-list">
            <li v-for="r in actor.top_routes" :key="r.route">
              <span data-field="actor.route.name">{{ r.route }}</span>
              <a class="count-link" data-field="actor.route.turns" href="#turns" @click.prevent="setFilter({ route: r.route })">{{ fmtInt(r.turns) }}</a>
            </li>
          </ul>
        </div>
        <div>
          <p v-if="hasCadence" class="cadence-line">A request every <span data-field="actor.cadence.median">{{ fmtMs(actor.activity.iri_median_ms) }}</span>. Variation <span data-field="actor.cadence.variation">{{ actor.activity.iri_cv === null || actor.activity.iri_cv === undefined ? '—' : fmtConf(actor.activity.iri_cv) }}</span>, where a person usually sits near 1.0 or more.</p>
          <p v-else class="cadence-line">Only one turn so far.</p>
        </div>
      </div>
    </section>

    <section class="panel" aria-label="Windside score">
      <h3 class="panel-title">Windside score</h3>
      <div v-if="actor.score">
        <div class="score-line"><span class="score-value" data-field="actor.score.value" :class="{ 'is-malicious': actor.score.verdict === 'hostile' }">{{ fmtConf(actor.score.value) }}</span></div>
        <p class="score-line">threshold <span data-field="actor.score.threshold">{{ fmtConf(actor.score.threshold) }}</span>, model <span data-field="actor.score.model">{{ actor.score.model_version }}</span>, <span data-field="summary.mode">{{ mode }}</span></p>
        <div class="score-meter" :style="`--score:${actor.score.value};--threshold:${actor.score.threshold}`" aria-hidden="true"></div>
        <p v-if="actor.explanation" class="detail-summary" data-field="actor.score.explanation">{{ actor.explanation.text }}</p>
        <p v-if="actor.explanation && actor.explanation.explained_by" class="explained-tag">explained by <span data-field="actor.score.explained_by">{{ actor.explanation.explained_by }}</span></p>
        <ul v-if="actor.score.top.length > 0" class="feature-list">
          <li v-for="f in actor.score.top" :key="f.name" class="feature-row">
            <span data-field="actor.feature.phrase">{{ f.phrase }}</span>
            <span class="signal-name" data-field="actor.feature.name">{{ f.name }}</span>
            <span class="feature-value" data-field="actor.feature.value">{{ f.value === null || f.value === undefined ? '—' : String(f.value) }}</span>
          </li>
        </ul>
      </div>
      <div v-else>
        <div class="score-line"><span class="score-value" data-field="actor.score.value">&mdash;</span></div>
        <p class="score-line">not enough turns to score</p>
      </div>
    </section>

    <section class="panel" aria-label="Labels">
      <h3 class="panel-title">Labels</h3>
      <p v-if="actor.proposal" class="panel-sentence">Proposed <span data-field="actor.proposal.label" :class="{ 'is-malicious': actor.proposal.label === 'malicious' }">{{ actor.proposal.label }}</span> at <span data-field="actor.proposal.confidence">{{ fmtConf(actor.proposal.confidence) }}</span>. {{ operatorLabel ? 'A person has weighed in.' : 'No person has confirmed it yet.' }}</p>
      <p v-else class="panel-sentence">No proposal.</p>
      <template v-if="actor.proposal">
        <p class="detail-summary" data-field="actor.proposal.reason">{{ actor.proposal.reason }}</p>
        <p v-if="actor.proposal.model" class="explained-tag">explained by <span data-field="actor.proposal.explained_by">{{ actor.proposal.model }}</span></p>
      </template>
      <div v-if="canDecide" class="decisions decisions-row" role="group" aria-label="Your decision">
        <button type="button" class="decision" data-action="confirm" data-field="decision.action" :disabled="disconnected" @click="$emit('decide', 'confirm')">It's an attack<kbd>1</kbd></button>
        <button type="button" class="decision" data-action="benign" data-field="decision.action" :disabled="disconnected" @click="$emit('decide', 'benign')">It's fine<kbd>2</kbd></button>
        <button type="button" class="decision" data-action="unknown" data-field="decision.action" :disabled="disconnected" @click="$emit('decide', 'unknown')">Not sure<kbd>3</kbd></button>
      </div>
      <div class="table-wrap"><table class="dense-table">
        <thead><tr><th>When</th><th>Source</th><th>Label</th><th>Confidence</th><th>Note</th></tr></thead>
        <tbody>
          <tr v-for="l in actor.labels" :key="`${l.source}:${l.at}`">
            <td><time class="time" data-field="actor.label.at">{{ fmtTime(l.at) }}</time></td>
            <td data-field="actor.label.source">{{ l.source }}</td>
            <td><span data-field="actor.label.value" :class="{ 'is-malicious': l.label === 'malicious' }">{{ l.label }}</span></td>
            <td class="mono-cell" data-field="actor.label.confidence">{{ fmtConf(l.confidence) }}</td>
            <td data-field="actor.label.note">{{ l.note || '—' }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <section class="panel" aria-label="Decisions">
      <h3 class="panel-title">Decisions</h3>
      <p v-if="latestDecision" class="panel-sentence">{{ decisionVerb }} by <span data-field="actor.decision.by">{{ decisionBy }}</span> at <span data-field="actor.decision.since">{{ fmtTime(latestDecision.created) }}</span>. {{ latestDecision.active ? 'Still active.' : 'Expired.' }}</p>
      <p v-else class="panel-sentence">No decisions.</p>
      <div class="table-wrap"><table class="dense-table">
        <thead><tr><th>Rule</th><th>Scope</th><th>Action</th><th>Since</th><th>Expires</th><th>Applied</th></tr></thead>
        <tbody>
          <tr v-for="d in actor.decisions" :key="`${d.rule}:${d.created}`">
            <td data-field="actor.decision.rule">{{ d.rule }}</td>
            <td data-field="actor.decision.scope">{{ d.scope }}</td>
            <td><span data-field="actor.decision.action" :class="{ 'is-malicious': isActing(d.action) }">{{ d.action }}</span></td>
            <td><time class="time" data-field="actor.decision.since">{{ fmtTime(d.created) }}</time></td>
            <td class="mono-cell" data-field="actor.decision.expires">{{ fmtTtl(d.expires - d.created) }}</td>
            <td data-field="actor.decision.applied">{{ d.active ? 'yes' : 'no' }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <section class="panel" aria-label="Similar actors">
      <h3 class="panel-title">Similar actors</h3>
      <p class="panel-sentence"><a class="count-link" data-field="actor.similar.count" href="#similar" @click.prevent>{{ fmtInt(actor.similar.length) }}</a> others in the same cluster. Same network and request shape, nothing more.</p>
      <div class="table-wrap"><table class="dense-table">
        <thead><tr><th>Actor</th><th>Kind</th><th>Score</th><th>Turns</th><th>Last seen</th><th>State</th></tr></thead>
        <tbody>
          <tr v-for="s in actor.similar" :key="s.id">
            <td><a class="time" data-field="actor.similar.id" :href="`#/actors/${encodeURIComponent(s.id)}`">{{ s.id }}</a></td>
            <td data-field="actor.similar.kind">{{ s.kind }}</td>
            <td class="mono-cell" data-field="actor.similar.score">{{ s.score === null || s.score === undefined ? '—' : fmtConf(s.score) }}</td>
            <td><a class="count-link" data-field="actor.similar.turns" :href="`#/actors/${encodeURIComponent(s.id)}`">{{ fmtInt(s.turns) }}</a></td>
            <td><time class="time" data-field="actor.similar.last_seen">{{ fmtTime(Math.floor(s.last / 1000000)) }}</time></td>
            <td data-field="actor.similar.state">{{ similarState(s.state) }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <section id="turns" class="panel panel-wide" aria-label="Turns">
      <h3 class="panel-title">Turns</h3>
      <p class="panel-sentence">The latest {{ Math.min(20, turnsTotal) }} of <a class="count-link" data-field="actor.turns" href="#turns" @click.prevent="clearFilter">{{ fmtInt(turnsTotal) }}</a>. Each row opens its trace.</p>
      <div class="table-wrap"><table class="dense-table">
        <thead><tr><th>Turn</th><th>Time</th><th>Method</th><th>Route</th><th>Status</th><th>Flags</th><th>Verdict</th><th></th></tr></thead>
        <tbody>
          <tr v-for="(t, i) in turnsRows" :key="t.row" class="turn-row" :class="{ 'is-cited': t.cited }" :id="`ad-turn-${i}`">
            <td class="turn-index">{{ i }}</td>
            <td v-if="t.trace"><a class="time" data-field="turn.at" :href="`${consolePrefix}/ui/trace/${t.trace}`">{{ fmtMillis(t.at) }}</a></td>
            <td v-else><span class="time" data-field="turn.at">{{ fmtMillis(t.at) }}</span></td>
            <td class="mono-cell" data-field="turn.method">{{ t.method }}</td>
            <td class="mono-cell" data-field="turn.route">{{ t.route }}</td>
            <td class="turn-status" data-field="turn.status" :class="{ 'is-error': t.status >= 400 }">{{ t.status }}</td>
            <td class="turn-flags" data-field="turn.flags">{{ t.flags.map((f) => f.phrase).join(', ') }}</td>
            <td class="mono-cell" data-field="turn.verdict" :title="t.note">{{ verdictWord(t.verdict) }}</td>
            <td class="turn-cited">{{ t.cited ? 'cited' : '' }}</td>
            <td hidden data-field="turn.id">{{ t.trace || '' }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { fmtClock, fmtConf, fmtDur, fmtInt, fmtMillis, fmtMs, fmtTime, verdictWord } from './fmt.js'
import { getActorTurns } from './api.js'

const props = defineProps({
  actor: { type: Object, default: null },
  actorId: { type: String, required: true },
  tab: { type: String, required: true },
  notFound: { type: Boolean, required: true },
  canDecide: { type: Boolean, required: true },
  disconnected: { type: Boolean, required: true },
  consolePrefix: { type: String, required: true },
  mode: { type: String, required: true },
})

const emit = defineEmits(['decide', 'block', 'unblock', 'down'])

const turnsFilter = ref(null)
const turnsRows = ref([])
const turnsTotal = ref(0)
const copiedKey = ref(null)
let copyTimer = null

function resetTurns() {
  turnsFilter.value = null
  if (props.actor) {
    turnsRows.value = props.actor.turns
    turnsTotal.value = props.actor.turn_total
  } else {
    turnsRows.value = []
    turnsTotal.value = 0
  }
}

watch(
  () => props.actor,
  () => resetTurns(),
  { immediate: true },
)

async function setFilter(filter) {
  if (!props.actor || props.disconnected) return
  turnsFilter.value = filter
  try {
    const v = await getActorTurns(props.actor.id, filter)
    turnsRows.value = v.turns
    turnsTotal.value = v.total
  } catch (err) {
    if (err && err.message === 'logged out') return
    emit('down')
  }
}

function clearFilter() {
  if (!props.actor || turnsFilter.value === null) return
  resetTurns()
}

const KIND_NOUNS = {
  tag: 'session tag',
  session: 'session id',
  principal: 'login',
  credential: 'API credential',
  net: 'network address',
  ja4_asn: 'network signature',
  shape_net: 'request shape',
  ua_net: 'user-agent group',
}

const identityMethod = computed(() => {
  if (!props.actor || props.actor.bindings.length === 0) return 'nothing yet'
  const kind = props.actor.bindings[0].kind
  return KIND_NOUNS[kind] || kind
})

const identityArticle = computed(() => {
  if (!props.actor || props.actor.bindings.length === 0) return ''
  return /^[aeiou]/i.test(identityMethod.value) ? 'an' : 'a'
})

const identityCameBack = computed(() => {
  if (!props.actor || props.actor.bindings.length === 0) return ''
  return props.actor.bindings[0].returned ? 'that came back' : "that hasn't come back yet"
})

function bindingState(b) {
  if (b.provisional) return 'provisional'
  if (b.returned) return 'returned'
  return 'seen'
}

const UA_NAMES = {
  chromium: 'Chrome',
  firefox: 'Firefox',
  safari: 'Safari',
  other_browser: 'a browser',
  library: 'a script',
}

const clientSentence = computed(() => {
  const c = props.actor ? props.actor.client : null
  if (!c || !c.ua_class) return 'It sent no user agent.'
  const name = UA_NAMES[c.ua_class] || c.ua_class
  if (c.ja4_hostile) return `It says it is ${name}. Its connection says otherwise.`
  return `It says it is ${name}.`
})

const shapeLine = computed(() => {
  const c = props.actor ? props.actor.client : null
  if (!c || !c.shape_prefix) return '—'
  const n = c.shape_count
  return `${c.shape_prefix}, ${n} shape${n === 1 ? '' : 's'} across all turns`
})

const activityTail = computed(() => {
  const a = props.actor ? props.actor.activity : null
  if (!a || a.turns === 0) return ''
  return a.not_found * 2 > a.turns ? ", mostly hunting for files that don't exist" : ''
})

const histogramScale = computed(() => {
  if (!props.actor) return 1
  return Math.max(1, ...props.actor.histogram.map((b) => b.total))
})

function inBucket(hourStart) {
  const at = props.actor ? props.actor.marker_at : null
  return at !== null && at !== undefined && at >= hourStart && at < hourStart + 3600
}

const statusShares = computed(() => {
  const a = props.actor ? props.actor.activity : null
  if (!a || a.turns === 0) return { hostile: 0, ok: 0, blocked: 0 }
  const counted = a.not_found + a.ok_2xx + a.redirects + a.denied + a.limited + a.errors_5xx
  const other = Math.max(0, a.turns - counted)
  return {
    hostile: (a.not_found + a.errors_5xx + other) / a.turns,
    ok: (a.ok_2xx + a.redirects) / a.turns,
    blocked: (a.denied + a.limited) / a.turns,
  }
})

const hasCadence = computed(() => {
  const a = props.actor ? props.actor.activity : null
  return !!a && a.iri_median_ms !== null && a.iri_median_ms !== undefined
})

const operatorLabel = computed(() => {
  if (!props.actor) return null
  return props.actor.labels.find((l) => l.source === 'operator') || null
})

function isActing(action) {
  return action === 'block' || action === 'rate_limit' || action === 'challenge'
}

const ACTION_VERBS = {
  block: 'Blocked',
  rate_limit: 'Rate-limited',
  challenge: 'Challenged',
}

const latestDecision = computed(() => {
  if (!props.actor || props.actor.decisions.length === 0) return null
  return props.actor.decisions.reduce((a, b) => (b.created > a.created ? b : a))
})

const decisionVerb = computed(() => {
  if (!latestDecision.value) return ''
  const action = latestDecision.value.action
  return ACTION_VERBS[action] || action.charAt(0).toUpperCase() + action.slice(1)
})

const decisionBy = computed(() => {
  if (!latestDecision.value) return ''
  return latestDecision.value.rule === 'operator' ? 'your decision' : latestDecision.value.rule
})

function fmtTtl(s) {
  const t = Math.max(0, s)
  if (t >= 3600) return `+${Math.round(t / 3600)} h`
  return `+${Math.round(t / 60)} min`
}

function similarState(state) {
  if (state === 'stopped') return 'blocked'
  if (state === 'waiting') return 'proposal waiting'
  return 'watched'
}

function askUnblock() {
  if (window.confirm('Lift this block? The actor returns to watch.')) emit('unblock')
}

const rawTurnKeys = [
  'turn_id', 'session_key', 'ts_us', 'ts', 'peer_key', 'principal', 'verb', 'route',
  'status', 'latency_ms', 'bytes_in', 'bytes_out', 'req_shape', 'resp_shape', 'bound',
  'validation_failed', 'exception', 'auth_event', 'gate', 'ua_hash', 'dropped_since_last',
  'rules_matched', 'verdict', 'ruleset_hash', 'surface', 'is_asset', 'credential_kind',
  'credential_hash', 'credential_status', 'tag_id', 'tag_status', 'ip_hash', 'net_hash',
  'asn', 'country', 'ip_trust', 'ua_class', 'shape_hash', 'flags', 'ja4', 'ja4t', 'h2_fp',
  'remote_port', 'ts_ms', 'actor_id', 'cluster_key', 'ingest_seq',
]

function rawText(v) {
  if (v === null || v === undefined) return 'null'
  if (typeof v === 'boolean') return v ? '1' : '0'
  return String(v)
}

const rawActorRows = computed(() => {
  if (!props.actor) return []
  const triples = props.actor.score
    ? props.actor.score.top.map((f) => [f.name, f.value, f.gain])
    : null
  return [
    { key: 'id', value: props.actor.id },
    { key: 'opened_us', value: rawText(props.actor.opened) },
    { key: 'last_us', value: rawText(props.actor.last) },
    { key: 'merged_into', value: rawText(props.actor.merged_into) },
    { key: 'turns', value: rawText(props.actor.turns_held) },
    { key: 'confirmed', value: rawText(props.actor.confirmed) },
    { key: 'score', value: props.actor.score ? String(props.actor.score.value) : 'null' },
    { key: 'score_ts', value: props.actor.score ? String(props.actor.score.at) : 'null' },
    { key: 'score_top3', value: triples ? JSON.stringify(triples) : 'null' },
  ]
})

function rawBindingRows(b, i) {
  return [
    { key: `${b.kind}[${i}].value`, value: rawText(b.value) },
    { key: `${b.kind}[${i}].first_seen`, value: rawText(b.first_seen) },
    { key: `${b.kind}[${i}].last_seen`, value: rawText(b.last_seen) },
    { key: `${b.kind}[${i}].expires_at`, value: rawText(b.expires_at) },
    { key: `${b.kind}[${i}].returned`, value: rawText(b.returned) },
  ]
}

async function copyText(text, key) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
  copiedKey.value = key
  if (copyTimer) clearTimeout(copyTimer)
  copyTimer = setTimeout(() => {
    copiedKey.value = null
  }, 1500)
}
</script>
