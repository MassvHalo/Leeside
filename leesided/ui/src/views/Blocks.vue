<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { clock, del, get, left } from '../api.js'

const emit = defineEmits(['changed'])
const list = ref([])
const offset = ref(0) // server clock minus ours, so countdowns match leesided
const tick = ref(Date.now() / 1000)
const error = ref('')
let poll = null
let second = null

async function load() {
  try {
    const r = await get('/decisions')
    list.value = r.decisions
    offset.value = r.now - Date.now() / 1000
    error.value = ''
  } catch (e) {
    error.value = e.message
  }
}

async function unblock(d) {
  if (!confirm(`Lift the ${d.action} on ${d.scope} ${d.key}?`)) return
  try {
    await del(`/decisions/${d.scope}/${d.key}`)
  } catch (e) {
    if (e.status !== 404) error.value = e.message
  }
  await load()
  emit('changed')
}

const remaining = (d) => Math.max(0, Math.round(d.expires_at - (tick.value + offset.value)))

onMounted(() => {
  load()
  poll = setInterval(load, 5000)
  second = setInterval(() => (tick.value = Date.now() / 1000), 1000)
})
onUnmounted(() => {
  clearInterval(poll)
  clearInterval(second)
})
</script>

<template>
  <section>
    <div class="bar">
      <h2>Active blocks and rate limits</h2>
      <span class="grow" />
      <span class="muted">refreshes every 5 s</span>
    </div>
    <p class="muted">
      A block sticks to the session that tripped it for the rule's <code>block_min</code>; a rate limit sticks to its
      scope for <code>retry_after_s</code>. Lifting one only clears the sticky decision: if the rule still matches, the
      next request trips it again.
    </p>
    <div v-if="error" class="banner err">{{ error }}</div>
    <table class="grid">
      <thead>
        <tr><th>Action</th><th>Rule</th><th>Scope</th><th>Key</th><th>Mode</th><th>Since</th><th>Time left</th><th /></tr>
      </thead>
      <tbody>
        <tr v-for="d in list" :key="`${d.scope}/${d.key}`">
          <td><span :class="['pill', 'a-' + d.action]">{{ d.action }}</span></td>
          <td><a :href="`#/rules/${d.rule}`"><code>{{ d.rule }}</code></a> <span class="muted">v{{ d.rule_version }}</span></td>
          <td>{{ d.scope }}</td>
          <td><a :href="`#/traffic?${d.scope === 'session' ? 'session' : 'peer'}=${d.key}`"><code>{{ d.key }}</code></a></td>
          <td><span :class="['pill', 'm-' + d.mode]">{{ d.mode }}</span></td>
          <td class="muted">{{ clock(d.created_at) }}</td>
          <td><b>{{ left(remaining(d)) }}</b></td>
          <td><button class="small" @click="unblock(d)">Lift</button></td>
        </tr>
        <tr v-if="!list.length"><td colspan="8" class="muted">Nothing is blocked or rate limited right now.</td></tr>
      </tbody>
    </table>
  </section>
</template>
