<script setup>
import { ref } from 'vue'
import { setToken } from '../api.js'

const value = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const res = await fetch('/api/mode', { headers: { Authorization: `Bearer ${value.value.trim()}` } })
    if (res.status === 401) error.value = 'That token was rejected.'
    else if (!res.ok) error.value = `leesided answered ${res.status}.`
    else setToken(value.value.trim())
  } catch {
    error.value = 'Could not reach leesided.'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="login">
    <form class="card" @submit.prevent="submit">
      <h1>Leeside</h1>
      <p class="muted">Paste the API token. It is in <code>/etc/leeside/leesided.env</code> on the server.</p>
      <input v-model="value" type="password" placeholder="Bearer token" autocomplete="current-password" autofocus />
      <button class="primary" :disabled="!value.trim() || busy">Sign in</button>
      <p v-if="error" class="err-text">{{ error }}</p>
    </form>
  </div>
</template>
