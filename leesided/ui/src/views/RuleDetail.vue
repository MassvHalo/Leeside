<script setup>
import { computed, onMounted, ref } from 'vue'
import { ago, get, post, put } from '../api.js'
import RuleEditor from './RuleEditor.vue'

const props = defineProps({ id: { type: String, required: true } })
const emit = defineEmits(['changed'])

const data = ref(null)
const error = ref('')
const notice = ref('')
const openVersion = ref(null)

async function load() {
  error.value = ''
  try {
    data.value = await get(`/rules/${encodeURIComponent(props.id)}`)
  } catch (e) {
    error.value = e.status === 404 ? `No rule called ${props.id}.` : e.message
  }
}
onMounted(load)

const rule = computed(() => data.value?.rule)
const retired = computed(() => data.value?.state === 'retired')

async function act(fn, done) {
  error.value = ''
  notice.value = ''
  try {
    await fn()
    notice.value = done
    await load()
    emit('changed')
  } catch (e) {
    error.value = e.body?.errors ? e.body.errors.map((x) => `${x.path}: ${x.message}`).join('; ') : e.message
  }
}

function setRuleMode(m) {
  if (m === rule.value.mode) return
  if (m === 'enforce' && !confirm(`Put ${props.id} in enforce? It will ${rule.value.action} when it matches and the global mode is enforce.`)) return
  act(() => put(`/rules/${encodeURIComponent(props.id)}`, { ...rule.value, mode: m }), `Mode set to ${m}.`)
}

function retire() {
  if (!confirm(`Retire ${props.id}? It stops being evaluated.`)) return
  act(() => post(`/rules/${encodeURIComponent(props.id)}/retire`), 'Retired.')
}

function accept(mode) {
  act(() => post(`/rules/${encodeURIComponent(props.id)}/accept`, { mode }), `Accepted as ${mode}.`)
}

function save(body) {
  return act(() => put(`/rules/${encodeURIComponent(props.id)}`, body), 'Saved as a new version.')
}

// stats_24h is one row per (hour, version, mode); sum for the headline.
const totals = computed(() => {
  const s = data.value?.stats_24h || []
  return s.reduce(
    (t, r) => ({ matched: t.matched + r.matched, would: t.would + r.would_act, acted: t.acted + r.acted }),
    { matched: 0, would: 0, acted: 0 },
  )
})
const hourLabel = (h) => new Date(h * 3600 * 1000).toLocaleString([], { hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short', hour12: false })
</script>

<template>
  <section>
    <p class="crumbs"><a href="#/rules">Rules</a> / <code>{{ id }}</code></p>
    <div v-if="error" class="banner err">{{ error }}</div>
    <div v-if="notice" class="banner ok">{{ notice }}</div>
    <template v-if="data">
      <div class="bar">
        <h2><code>{{ data.id }}</code></h2>
        <span :class="['pill', 'st-' + data.state]">{{ data.state }}</span>
        <span :class="['pill', 'a-' + rule.action]">{{ rule.action }}</span>
        <span class="muted">v{{ data.version }} · updated {{ ago(data.updated_at) }}</span>
      </div>
      <p class="note">{{ rule.note }}</p>

      <div class="row actions">
        <div v-if="!retired && data.state === 'active'">
          <span class="label">Rule mode</span>
          <div class="seg">
            <button v-for="m in ['monitor', 'shadow', 'enforce']" :key="m" :class="['m-' + m, { on: rule.mode === m }]" @click="setRuleMode(m)">{{ m }}</button>
          </div>
        </div>
        <div v-if="data.state === 'proposed'">
          <span class="label">Accept as</span>
          <div class="seg">
            <button v-for="m in ['monitor', 'shadow', 'enforce']" :key="m" :class="'m-' + m" @click="accept(m)">{{ m }}</button>
          </div>
        </div>
        <span class="grow" />
        <button v-if="!retired" class="danger" @click="retire">Retire</button>
      </div>

      <div class="cards">
        <div class="card stat"><span class="big">{{ totals.matched }}</span><span class="muted">matched, 24 h</span></div>
        <div class="card stat"><span class="big">{{ totals.would }}</span><span class="muted">would act</span></div>
        <div class="card stat"><span class="big">{{ totals.acted }}</span><span class="muted">acted (enforced)</span></div>
      </div>

      <h3>Definition</h3>
      <RuleEditor v-if="!retired" :initial="rule" :fixed-id="data.id" save-label="Save new version" @save="save" />
      <pre v-else class="json">{{ JSON.stringify(rule, null, 2) }}</pre>

      <h3>Last 24 hours by hour</h3>
      <table class="grid" v-if="data.stats_24h.length">
        <thead><tr><th>Hour</th><th>Version</th><th>Mode</th><th>Matched</th><th>Would act</th><th>Acted</th></tr></thead>
        <tbody>
          <tr v-for="s in data.stats_24h" :key="`${s.hour}-${s.version}-${s.mode}`">
            <td>{{ hourLabel(s.hour) }}</td><td>v{{ s.version }}</td>
            <td><span :class="['pill', 'm-' + s.mode]">{{ s.mode }}</span></td>
            <td>{{ s.matched }}</td><td>{{ s.would_act }}</td><td>{{ s.acted }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">No matches in the last 24 hours. Stats flush every 10 s.</p>

      <h3>Versions</h3>
      <table class="grid">
        <thead><tr><th>Version</th><th>State</th><th>By</th><th>Reason</th><th>When</th><th /></tr></thead>
        <tbody>
          <template v-for="v in data.versions" :key="v.version">
            <tr>
              <td>v{{ v.version }}</td>
              <td><span :class="['pill', 'st-' + v.state]">{{ v.state }}</span></td>
              <td>{{ v.changed_by }}</td>
              <td class="muted">{{ v.reason || '—' }}</td>
              <td class="muted">{{ ago(v.changed_at) }}</td>
              <td><button class="ghost small" @click="openVersion = openVersion === v.version ? null : v.version">{{ openVersion === v.version ? 'Hide' : 'Body' }}</button></td>
            </tr>
            <tr v-if="openVersion === v.version"><td colspan="6"><pre class="json">{{ JSON.stringify(v.body, null, 2) }}</pre></td></tr>
          </template>
        </tbody>
      </table>
    </template>
  </section>
</template>
