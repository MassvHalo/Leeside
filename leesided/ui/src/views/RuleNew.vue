<script setup>
import { ref } from 'vue'
import { post } from '../api.js'
import RuleEditor from './RuleEditor.vue'

const emit = defineEmits(['changed'])
const error = ref('')

// Starts in shadow: it is evaluated and counted, never acted on.
const template = {
  id: 'my-new-rule',
  note: 'What this rule catches',
  mode: 'shadow',
  action: 'block',
  block_min: 10,
  match: { route: ['venues.show'], verb: ['GET'], principal: 'any' },
  when: {
    scope: 'peer',
    window_s: 600,
    count: { status: ['4xx'] },
    gte: 10,
  },
  origin: { kind: 'operator' },
}

async function create(body) {
  error.value = ''
  try {
    await post('/rules', body)
    emit('changed')
    window.location.hash = `#/rules/${encodeURIComponent(body.id)}`
  } catch (e) {
    error.value = e.body?.errors ? e.body.errors.map((x) => `${x.path}: ${x.message}`).join('; ') : e.message
  }
}
</script>

<template>
  <section>
    <p class="crumbs"><a href="#/rules">Rules</a> / new</p>
    <h2>New rule</h2>
    <p class="muted">
      The rule is created as active, in the mode you give it. Field reference:
      <code>leesided/docs/rules.md</code>.
    </p>
    <div v-if="error" class="banner err">{{ error }}</div>
    <RuleEditor :initial="template" save-label="Create rule" @save="create" />
  </section>
</template>
