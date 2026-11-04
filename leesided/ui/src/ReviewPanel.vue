<template>
  <header v-if="queue === null" class="page-head page-head-tabs" aria-busy="true">
    <div class="page-head-text"><span class="skeleton skeleton-title"></span></div>
    <nav class="tabs" aria-label="Page sections">
      <a class="tab" href="#/review" :aria-current="tab === 'queue' ? 'page' : null">Queue</a>
      <a class="tab" href="#/review/decided" :aria-current="tab === 'decided' ? 'page' : null">Decided</a>
    </nav>
  </header>
  <header v-else-if="tab === 'decided'" class="page-head page-head-tabs">
    <div class="page-head-text">
      <p class="crumb">Windside <span aria-hidden="true">&rsaquo;</span> <b>Review</b></p>
      <div class="headline-row">
        <h1 class="headline">
          <span class="headline-dim"><span data-field="decided.total">{{ fmtInt(decided.total) }}</span> decided.</span>
          <span class="headline-rest">You agreed with the proposal on <span data-field="decided.agreed">{{ fmtInt(decided.agreed) }}</span>.</span>
        </h1>
      </div>
    </div>
    <nav class="tabs" aria-label="Page sections">
      <a class="tab" href="#/review">Queue<span class="tab-count">{{ fmtInt(queueTotal) }}</span></a>
      <a class="tab" href="#/review/decided" aria-current="page">Decided<span class="tab-count">{{ fmtInt(decided.total) }}</span></a>
    </nav>
  </header>
  <header v-else-if="queueTotal === 0" class="page-head page-head-tabs">
    <div class="page-head-text">
      <p class="crumb">Windside <span aria-hidden="true">&rsaquo;</span> <b>Review</b></p>
      <div class="headline-row"><h1 class="headline">Nothing waiting.</h1></div>
      <p class="subline">When a rule or Windside needs a person, it lands here in order.</p>
    </div>
    <nav class="tabs" aria-label="Page sections">
      <a class="tab" href="#/review" aria-current="page">Queue<span class="tab-count">0</span></a>
      <a class="tab" href="#/review/decided">Decided<span class="tab-count">{{ fmtInt(decided.total) }}</span></a>
    </nav>
  </header>
  <header v-else class="page-head page-head-tabs">
    <div class="page-head-text">
      <p class="crumb">Windside <span aria-hidden="true">&rsaquo;</span> <b>Review</b></p>
      <div class="headline-row">
        <h1 class="headline">
          <span class="headline-dim"><a class="count-link" href="#/review" data-field="queue.pending" @click.prevent="queueFilter = 'all'">{{ fmtInt(queueTotal) }}</a> waiting.</span>
          <span class="headline-rest">Rule and model disagree on <a class="count-link" href="#/review" data-field="queue.disagree" @click.prevent="queueFilter = 'disagree'">{{ fmtInt(queueDisagree) }}</a>.</span>
        </h1>
      </div>
    </div>
    <nav class="tabs" aria-label="Page sections">
      <a class="tab" href="#/review" aria-current="page">Queue<span class="tab-count">{{ fmtInt(queueTotal) }}</span></a>
      <a class="tab" href="#/review/decided">Decided<span class="tab-count">{{ fmtInt(decided.total) }}</span></a>
    </nav>
  </header>

  <div v-if="queue === null" class="workspace">
    <section class="queue" aria-busy="true">
      <ul class="queue-list skeleton-list">
        <li v-for="n in 5" :key="n" class="skeleton-item"><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line skeleton-short"></span></li>
      </ul>
    </section>
    <section class="detail" aria-busy="true">
      <span class="skeleton skeleton-title"></span>
      <div v-for="n in 4" :key="n" class="skeleton-row"><span class="skeleton skeleton-line"></span></div>
    </section>
  </div>

  <section v-else-if="tab === 'decided'" class="panel panel-flat" aria-label="Your past labels">
    <div class="filter-chips" role="group" aria-label="Filter">
      <button type="button" class="filter-chip" :aria-pressed="String(decidedFilter === 'all')" @click="decidedFilter = 'all'">All<span class="tab-count">{{ fmtInt(decided.total) }}</span></button>
      <button type="button" class="filter-chip" :aria-pressed="String(decidedFilter === 'agree')" @click="decidedFilter = 'agree'">Agree<span class="tab-count">{{ fmtInt(decided.agreed) }}</span></button>
      <button type="button" class="filter-chip" :aria-pressed="String(decidedFilter === 'disagree')" @click="decidedFilter = 'disagree'">Disagree<span class="tab-count">{{ fmtInt(decided.total - decided.agreed) }}</span></button>
    </div>
    <div class="table-wrap">
      <table class="dense-table">
        <thead><tr><th>Decided</th><th>Subject</th><th>Proposal said</th><th>Your label</th><th>Agreement</th></tr></thead>
        <tbody>
          <tr v-for="d in decidedRows" :key="`${d.scope}:${d.id}:${d.at}`">
            <td><time class="time" data-field="decision.at">{{ fmtTime(d.at) }}</time></td>
            <td><span data-field="subject.kind">{{ d.scope }}</span> <a class="time" data-field="queue.item.id" :href="`#/review/${d.scope}/${encodeURIComponent(d.id)}`">{{ d.id }}</a></td>
            <td v-if="d.proposal"><span data-field="proposal.label" :class="{ 'is-malicious': d.proposal === 'malicious' }">{{ d.proposal }}</span> <span v-if="d.proposal_confidence !== null && d.proposal_confidence !== undefined" class="time" data-field="proposal.confidence">{{ fmtConf(d.proposal_confidence) }}</span></td>
            <td v-else><span data-field="proposal.label">&mdash;</span></td>
            <td><span data-field="decision.action" :data-action="actionOf(d.operator)">{{ actionWord(d.operator) }}</span></td>
            <td><span class="agreement" data-field="decision.agreed" :data-agreed="String(d.agreed)">{{ d.agreed ? 'agree' : 'disagree' }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <div v-else class="workspace">
    <section class="queue" aria-label="Queue, in order">
      <p v-if="queueTotal === 0" class="episodes-none queue-none">The queue is empty</p>
      <ol v-else class="queue-list">
        <li v-for="item in visibleQueue" :key="`${item.scope}:${item.id}`">
          <button
            type="button"
            class="queue-item"
            :aria-current="keyOf(item) === selectedKey ? 'true' : null"
            @click="$emit('select', item.scope, item.id)"
          >
            <span class="queue-order">{{ queuePosition(item) }}</span>
            <span class="queue-text">
              <span class="queue-why" data-field="queue.item.why">{{ item.why_phrase }}</span>
              <span class="queue-subject"><span data-field="subject.kind">{{ item.scope }}</span> <span class="time" data-field="queue.item.id">{{ item.id }}</span></span>
              <span v-if="item.disagree" class="queue-disagree">rule and model disagree</span>
            </span>
            <span class="queue-label" :class="{ 'is-malicious': item.proposal && item.proposal.label === 'malicious' }">
              <template v-if="item.proposal"><span data-field="proposal.label">{{ item.proposal.label }}</span> <span data-field="proposal.confidence">{{ fmtConf(item.proposal.confidence) }}</span></template>
            </span>
          </button>
        </li>
      </ol>
    </section>

    <section v-if="itemLoading" class="detail" aria-busy="true">
      <span class="skeleton skeleton-title"></span>
      <div v-for="n in 4" :key="n" class="skeleton-row"><span class="skeleton skeleton-line"></span></div>
    </section>
    <section v-else-if="!item" class="detail detail-empty" aria-label="This proposal">
      <h2 class="detail-title">No proposal to look at.</h2>
      <p class="detail-summary">Your labels from earlier show under Decided, and each one teaches the next model.</p>
    </section>
    <section v-else class="detail review-detail" aria-label="This proposal" aria-live="polite">
      <header class="detail-head">
        <div class="detail-state">
          <span data-field="subject.kind">{{ item.scope === 'actor' ? 'Actor' : 'Cluster' }}</span>
          <a class="time subject-id" data-field="queue.item.id" :href="subjectHref">{{ item.id }}</a>
          <button type="button" class="copy" data-copy @click="copyId">{{ copied ? 'Copied' : 'Copy' }}</button>
          <a class="inline-more" :href="subjectHref">Open {{ item.scope }}<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></a>
        </div>
        <h2 v-if="item.proposal" class="detail-title">Proposed <span data-field="proposal.label" :class="{ 'is-malicious': item.proposal.label === 'malicious' }">{{ item.proposal.label }}</span> at <span data-field="proposal.confidence">{{ fmtConf(item.proposal.confidence) }}</span>.</h2>
        <h2 v-else class="detail-title">No proposal.</h2>
      </header>
      <div class="verdicts">
        <div class="verdict">
          <span class="step-label">Windside score</span>
          <span class="verdict-value" data-field="subject.score" :class="{ 'is-malicious': item.model.score >= item.model.threshold }">{{ fmtConf(item.model.score) }}</span>
          <span class="verdict-note">{{ item.model.score >= item.model.threshold ? 'past' : 'below' }} the threshold of <span data-field="subject.threshold">{{ fmtConf(item.model.threshold) }}</span></span>
        </div>
        <div class="verdict">
          <span class="step-label">Rule hits</span>
          <span class="verdict-value" data-field="subject.rule_hits">{{ item.model.rules_fired.names.length > 0 ? item.model.rules_fired.names.join(', ') : 'None' }}</span>
          <span class="verdict-note">{{ item.model.rules_fired.names.length > 0 ? 'fired on these turns' : 'no rule fired on these turns' }}</span>
        </div>
        <div class="verdict">
          <span class="step-label">Why it's in the queue</span>
          <span class="verdict-text" data-field="queue.item.why">{{ item.why_phrase || 'not in the queue' }}</span>
          <span v-if="item.disagree" class="verdict-note">the model and the rules disagree</span>
        </div>
      </div>
      <div v-if="item.proposal" class="signals">
        <h3 class="section-label">Signals, each checked against the turns it cites</h3>
        <ul class="signal-list">
          <li v-for="s in item.signals" :key="s.name" class="signal-row" :class="{ 'is-failed': !s.passed }">
            <span class="signal-mark" data-field="proposal.signal.passed" :data-passed="String(s.passed)">{{ s.passed ? 'pass' : 'fail' }}</span>
            <span class="signal-body">
              <span class="signal-name" data-field="proposal.signal.name" :title="s.phrase">{{ s.name }}</span>
              <p v-if="!s.passed" class="signal-reason" data-field="proposal.signal.failed_reason">{{ s.failed_reason }}</p>
            </span>
            <span class="signal-turns" data-field="proposal.signal.turns">
              <template v-if="s.turns.length === 0"><span class="signal-window">the whole window</span></template>
              <template v-else>
                <a v-for="t in inTable(s.turns)" :key="t.row" class="turn-link" :href="`#rv-turn-${rowIndex(t.row)}`" @click.prevent="jumpToTurn(t.row)">{{ rowIndex(t.row) }}</a>
                <span v-if="s.turns.length > inTable(s.turns).length" class="signal-window">{{ s.turns.length - inTable(s.turns).length }} older turns</span>
              </template>
            </span>
          </li>
        </ul>
      </div>
      <div v-if="item.proposal" class="reason">
        <p class="detail-summary" data-field="proposal.reason">{{ item.proposal.reason }}</p>
        <p v-if="item.proposal.model" class="explained-tag">explained by <span data-field="proposal.explained_by">{{ item.proposal.model }}</span></p>
      </div>
      <div class="decision-bar">
        <div v-if="canDecide" class="decisions decisions-row" role="group" aria-label="Your decision">
          <button type="button" class="decision" data-action="confirm" data-field="decision.action" :disabled="disconnected" @click="$emit('decide', 'confirm')">It's an attack<kbd>1</kbd></button>
          <button type="button" class="decision" data-action="benign" data-field="decision.action" :disabled="disconnected" @click="$emit('decide', 'benign')">It's fine<kbd>2</kbd></button>
          <button type="button" class="decision" data-action="unknown" data-field="decision.action" :disabled="disconnected" @click="$emit('decide', 'unknown')">Not sure<kbd>3</kbd></button>
        </div>
        <button type="button" class="next-button" :disabled="disconnected" @click="$emit('next', 1)">Next<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></button>
        <span class="key-hint"><kbd>j</kbd><kbd>k</kbd> move</span>
      </div>
      <div class="review-turns">
        <h3 class="section-label">Last 20 turns from this subject</h3>
        <div class="table-wrap">
          <table class="dense-table">
            <thead><tr><th>Turn</th><th>Time</th><th>Method</th><th>Route</th><th>Status</th><th>Flags</th><th>Verdict</th><th></th></tr></thead>
            <tbody>
              <tr v-for="(t, i) in item.evidence.turns" :key="t.row" class="turn-row" :class="{ 'is-cited': t.cited }" :id="`rv-turn-${i}`">
                <td class="turn-index">{{ i }}</td>
                <td v-if="t.trace"><a class="time" data-field="turn.at" :href="`${consolePrefix}/trace/${t.trace}`">{{ fmtMillis(t.at) }}</a></td>
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
          </table>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { fmtConf, fmtInt, fmtMillis, fmtTime, verdictWord } from './fmt.js'

const props = defineProps({
  queue: { type: Array, default: null },
  queueTotal: { type: Number, required: true },
  queueDisagree: { type: Number, required: true },
  decided: { type: Object, required: true },
  item: { type: Object, default: null },
  itemLoading: { type: Boolean, required: true },
  tab: { type: String, required: true },
  selectedKey: { type: String, default: null },
  canDecide: { type: Boolean, required: true },
  disconnected: { type: Boolean, required: true },
  consolePrefix: { type: String, required: true },
})

defineEmits(['select', 'next', 'decide'])

const queueFilter = ref('all')
const decidedFilter = ref('all')
const copied = ref(false)
let copyTimer = null

const visibleQueue = computed(() => {
  if (!props.queue) return []
  if (queueFilter.value === 'disagree') return props.queue.filter((item) => item.disagree)
  return props.queue
})

const decidedRows = computed(() => {
  if (decidedFilter.value === 'agree') return props.decided.items.filter((d) => d.agreed)
  if (decidedFilter.value === 'disagree') return props.decided.items.filter((d) => !d.agreed)
  return props.decided.items
})

const subjectHref = computed(() => {
  if (!props.item) return '#'
  if (props.item.scope === 'actor') return `#/actors/${encodeURIComponent(props.item.id)}`
  return `${props.consolePrefix}/clusters/${encodeURIComponent(props.item.id)}`
})

function keyOf(item) {
  return `${item.scope}:${item.id}`
}

function queuePosition(item) {
  if (!props.queue) return 0
  return props.queue.findIndex((q) => keyOf(q) === keyOf(item)) + 1
}

function rowIndex(rowid) {
  if (!props.item) return -1
  return props.item.evidence.turns.findIndex((t) => t.row === rowid)
}

function inTable(turns) {
  return turns.filter((t) => rowIndex(t.row) >= 0)
}

function actionOf(operator) {
  if (operator === 'malicious') return 'confirm'
  if (operator === 'benign') return 'benign'
  return 'unknown'
}

function actionWord(operator) {
  if (operator === 'malicious') return "It's an attack"
  if (operator === 'benign') return "It's fine"
  return 'Not sure'
}

function jumpToTurn(rowid) {
  const i = rowIndex(rowid)
  if (i < 0) return
  const el = document.getElementById(`rv-turn-${i}`)
  if (el) {
    el.scrollIntoView({ block: 'nearest' })
    // Highlight without routing: replaceState sets :target, no hashchange.
    window.history.replaceState(null, '', `#rv-turn-${i}`)
  }
}

async function copyId() {
  if (!props.item) return
  try {
    await navigator.clipboard.writeText(props.item.id)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = props.item.id
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
  copied.value = true
  if (copyTimer) clearTimeout(copyTimer)
  copyTimer = setTimeout(() => {
    copied.value = false
  }, 1500)
}

watch(
  () => props.item,
  () => {
    copied.value = false
  },
)
</script>
