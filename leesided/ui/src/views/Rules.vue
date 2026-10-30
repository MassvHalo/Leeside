<script setup>
import { onMounted, ref, watch } from 'vue'
import { ago, get } from '../api.js'

const state = ref('all')
const rules = ref([])
const invalid = ref([])
const error = ref('')

async function load() {
  error.value = ''
  try {
    const r = await get(`/rules?state=${state.value}&invalid=true`)
    rules.value = r.rules
    invalid.value = r.invalid || []
  } catch (e) {
    error.value = e.message
  }
}
const open = (id) => (window.location.hash = `#/rules/${encodeURIComponent(id)}`)

onMounted(load)
watch(state, load)
</script>

<template>
  <section>
    <div class="bar">
      <h2>Rules</h2>
      <div class="seg small">
        <button v-for="s in ['all', 'active', 'proposed', 'retired']" :key="s" :class="{ on: state === s }" @click="state = s">{{ s }}</button>
      </div>
      <span class="grow" />
      <a class="btn primary" href="#/new">New rule</a>
    </div>
    <div v-if="error" class="banner err">{{ error }}</div>
    <div v-if="invalid.length" class="banner warn">
      {{ invalid.length }} stored rule(s) failed to load:
      <span v-for="i in invalid" :key="i.id"><a :href="`#/rules/${i.id}`">{{ i.id }}</a> </span>
    </div>
    <table class="grid">
      <thead>
        <tr><th>Rule</th><th>State</th><th>Mode</th><th>Action</th><th>Version</th><th>Origin</th><th>Updated</th></tr>
      </thead>
      <tbody>
        <tr v-for="r in rules" :key="r.id" class="link" @click="open(r.id)">
          <td><code>{{ r.id }}</code></td>
          <td><span :class="['pill', 'st-' + r.state]">{{ r.state }}</span></td>
          <td><span :class="['pill', 'm-' + r.mode]">{{ r.mode }}</span></td>
          <td><span :class="['pill', 'a-' + r.action]">{{ r.action }}</span></td>
          <td>v{{ r.version }}</td>
          <td class="muted">{{ r.origin_kind }}</td>
          <td class="muted">{{ ago(r.updated_at) }}</td>
        </tr>
        <tr v-if="!rules.length"><td colspan="7" class="muted">No rules in this state.</td></tr>
      </tbody>
    </table>
  </section>
</template>
