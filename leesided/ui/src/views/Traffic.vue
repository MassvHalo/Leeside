<script setup>
import { onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { clock, get } from '../api.js'

const FIELDS = ['peer', 'session', 'route', 'verdict']

function fromHash() {
  const q = new URLSearchParams(location.hash.split('?')[1] || '')
  return Object.fromEntries(FIELDS.map((f) => [f, q.get(f) || '']))
}

const filters = reactive(fromHash())
const turns = ref([])
const live = ref(true)
const error = ref('')
let poll = null

function query() {
  const q = new URLSearchParams({ limit: '200' })
  for (const f of FIELDS) if (filters[f]) q.set(f, filters[f])
  return q.toString()
}

async function load() {
  try {
    turns.value = (await get(`/turns?${query()}`)).turns
    error.value = ''
  } catch (e) {
    error.value = e.message
  }
}

// Keep the filters in the URL so a filtered view can be linked to.
watch(filters, () => {
  const q = new URLSearchParams()
  for (const f of FIELDS) if (filters[f]) q.set(f, filters[f])
  const s = q.toString()
  history.replaceState(null, '', `#/traffic${s ? '?' + s : ''}`)
  load()
})
watch(live, (on) => {
  clearInterval(poll)
  if (on) poll = setInterval(load, 3000)
})

const onHash = () => Object.assign(filters, fromHash())
onMounted(() => {
  load()
  poll = setInterval(load, 3000)
  window.addEventListener('hashchange', onHash)
})
onUnmounted(() => {
  clearInterval(poll)
  window.removeEventListener('hashchange', onHash)
})

const set = (f, v) => (filters[f] = filters[f] === v ? '' : v)
const clear = () => FIELDS.forEach((f) => (filters[f] = ''))
const statusClass = (s) => (s >= 500 ? 's5' : s >= 400 ? 's4' : s >= 300 ? 's3' : 's2')
const boundText = (b) =>
  Array.isArray(b) && b.length ? b.map((x) => `${x.model || x.param}:${x.id_hash}`).join(' ') : ''
const matched = (m) => (Array.isArray(m) ? m : [])
</script>

<template>
  <section>
    <div class="bar">
      <h2>Traffic</h2>
      <span class="grow" />
      <label class="check"><input v-model="live" type="checkbox" /> live</label>
    </div>
    <div class="filters">
      <input v-model.lazy="filters.peer" placeholder="peer key" />
      <input v-model.lazy="filters.session" placeholder="session key" />
      <input v-model.lazy="filters.route" placeholder="route (e.g. venues.show)" />
      <select v-model="filters.verdict">
        <option value="">any verdict</option>
        <option value="allow">allow</option>
        <option value="block">block</option>
        <option value="rate_limit">rate_limit</option>
        <option value="challenge">challenge</option>
        <option value="none">no check (e.g. 404 before the gate)</option>
      </select>
      <button class="ghost" @click="clear">Clear</button>
    </div>
    <div v-if="error" class="banner err">{{ error }}</div>
    <p class="muted">Newest first, up to 200. Click a peer, session or route to filter on it.</p>
    <table class="grid dense">
      <thead>
        <tr><th>Time</th><th>Peer</th><th>Session</th><th>Request</th><th>Status</th><th>Verdict</th><th>Matched</th><th>Detail</th></tr>
      </thead>
      <tbody>
        <tr v-for="t in turns" :key="t.session_key + t.ts">
          <td class="muted">{{ clock(t.ts) }}</td>
          <td><a class="key" @click="set('peer', t.peer_key)">{{ t.peer_key.slice(0, 8) }}</a></td>
          <td><a class="key" @click="set('session', t.session_key)">{{ t.session_key.slice(0, 8) }}</a></td>
          <td><span class="verb">{{ t.verb }}</span> <a class="key" @click="set('route', t.route)">{{ t.route }}</a></td>
          <td><span :class="['status', statusClass(t.status)]">{{ t.status }}</span></td>
          <td><span v-if="t.verdict" :class="['pill', 'a-' + t.verdict]">{{ t.verdict }}</span><span v-else class="muted">—</span></td>
          <td>
            <span v-for="m in matched(t.rules_matched)" :key="m.rule" class="tag" :title="`${m.action} in ${m.mode}${m.proposed ? ' (proposed)' : ''}`">
              <a :href="`#/rules/${m.rule}`">{{ m.rule }}</a>
            </span>
          </td>
          <td class="muted small-text">
            <span v-if="t.exception">{{ t.exception }} </span>
            <span v-if="t.auth_event">{{ t.auth_event }} </span>
            <span v-if="t.validation_failed">invalid: {{ t.validation_failed.join(', ') }} </span>
            <span>{{ boundText(t.bound) }}</span>
          </td>
        </tr>
        <tr v-if="!turns.length"><td colspan="8" class="muted">No traffic matches.</td></tr>
      </tbody>
    </table>
  </section>
</template>
