<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { get, put, setToken, token } from './api.js'
import Login from './views/Login.vue'
import Rules from './views/Rules.vue'
import RuleDetail from './views/RuleDetail.vue'
import RuleNew from './views/RuleNew.vue'
import Blocks from './views/Blocks.vue'
import Traffic from './views/Traffic.vue'

// Hash routes: #/rules, #/rules/<id>, #/new, #/blocks, #/traffic?peer=..
const hash = ref(location.hash || '#/rules')
const onHash = () => (hash.value = location.hash || '#/rules')
const route = computed(() => {
  const path = hash.value.replace(/^#\/?/, '').split('?')[0]
  const parts = path.split('/').map(decodeURIComponent)
  return { name: parts[0] || 'rules', arg: parts[1] || null }
})

const health = ref(null)
const modeErr = ref('')
let timer = null

async function refreshHealth() {
  if (!token.value) return
  try {
    health.value = await get('/health')
  } catch {
    health.value = null
  }
}

async function setMode(m) {
  if (m === health.value?.mode) return
  if (m === 'enforce' && !confirm('Switch the global mode to enforce? Rules in enforce will start blocking.')) return
  modeErr.value = ''
  try {
    await put('/mode', { mode: m })
  } catch (e) {
    modeErr.value = e.message
  }
  refreshHealth()
}

onMounted(() => {
  window.addEventListener('hashchange', onHash)
  refreshHealth()
  timer = setInterval(refreshHealth, 5000)
})
onUnmounted(() => {
  window.removeEventListener('hashchange', onHash)
  clearInterval(timer)
})
watch(token, refreshHealth)

const tabs = [
  { name: 'rules', label: 'Rules' },
  { name: 'blocks', label: 'Blocks' },
  { name: 'traffic', label: 'Traffic' },
]
const activeTab = computed(() => (route.value.name === 'new' ? 'rules' : route.value.name))
</script>

<template>
  <Login v-if="!token" />
  <div v-else class="shell">
    <header class="top">
      <div class="brand">Leeside</div>
      <nav class="tabs">
        <a v-for="t in tabs" :key="t.name" :href="`#/${t.name}`" :class="{ on: activeTab === t.name }">
          {{ t.label }}
          <span v-if="t.name === 'blocks' && health?.decisions" class="count">{{ health.decisions }}</span>
        </a>
      </nav>
      <div class="mode" v-if="health">
        <span class="label">Global mode</span>
        <div class="seg">
          <button
            v-for="m in ['monitor', 'shadow', 'enforce']"
            :key="m"
            :class="['m-' + m, { on: health.mode === m }]"
            :disabled="m === 'enforce' && !health.enforce_allowed"
            @click="setMode(m)"
          >{{ m }}</button>
        </div>
      </div>
      <button class="ghost" @click="setToken('')">Sign out</button>
    </header>
    <div v-if="modeErr" class="banner err">{{ modeErr }}</div>
    <div class="stats" v-if="health">
      <span><b>{{ health.rules.loaded }}</b> rules loaded</span>
      <span>generation <b>{{ health.rules.generation }}</b></span>
      <span>hash <code>{{ health.rules.hash.slice(0, 12) }}</code></span>
      <span v-if="health.rules.invalid" class="warn"><b>{{ health.rules.invalid }}</b> invalid</span>
      <span><b>{{ health.check.total }}</b> checks</span>
      <span><b>{{ health.ingest.total }}</b> events</span>
      <span><b>{{ health.windows.sessions }}</b> sessions · <b>{{ health.windows.peers }}</b> peers</span>
      <span v-if="health.store.dropped" class="warn"><b>{{ health.store.dropped }}</b> dropped</span>
    </div>
    <main>
      <Rules v-if="route.name === 'rules' && !route.arg" />
      <RuleDetail v-else-if="route.name === 'rules'" :id="route.arg" :key="route.arg" @changed="refreshHealth" />
      <RuleNew v-else-if="route.name === 'new'" @changed="refreshHealth" />
      <Blocks v-else-if="route.name === 'blocks'" @changed="refreshHealth" />
      <Traffic v-else-if="route.name === 'traffic'" />
      <p v-else class="muted">Nothing here. <a href="#/rules">Back to rules</a></p>
    </main>
  </div>
</template>
