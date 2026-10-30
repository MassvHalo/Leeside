<script setup>
import { ref, watch } from 'vue'
import { post } from '../api.js'

// JSON editor for one rule body: parse locally, then the daemon's dry-run
// validator, which reports errors by field path.
const props = defineProps({
  initial: { type: Object, required: true },
  fixedId: { type: String, default: null },
  saveLabel: { type: String, default: 'Save' },
})
const emit = defineEmits(['save'])

const text = ref(JSON.stringify(props.initial, null, 2))
const errors = ref([])
const status = ref('')
const busy = ref(false)

watch(
  () => props.initial,
  (v) => (text.value = JSON.stringify(v, null, 2)),
)
watch(text, () => {
  status.value = ''
  errors.value = []
})

function parse() {
  try {
    const body = JSON.parse(text.value)
    if (props.fixedId && body.id !== props.fixedId) {
      errors.value = [{ path: 'id', message: `must stay ${props.fixedId}` }]
      return null
    }
    return body
  } catch (e) {
    errors.value = [{ path: '(json)', message: e.message }]
    return null
  }
}

async function validate() {
  const body = parse()
  if (!body) return null
  busy.value = true
  try {
    const r = await post('/rules/validate', body)
    errors.value = r.errors
    status.value = r.ok ? 'Valid.' : ''
    return r.ok ? body : null
  } catch (e) {
    errors.value = [{ path: '(request)', message: e.message }]
    return null
  } finally {
    busy.value = false
  }
}

async function save() {
  const body = await validate()
  if (!body) return
  if (body.mode === 'enforce' && props.initial.mode !== 'enforce' && !confirm('This saves the rule in enforce mode. Continue?')) return
  emit('save', body)
}

function reset() {
  text.value = JSON.stringify(props.initial, null, 2)
}
</script>

<template>
  <div class="editor">
    <textarea v-model="text" spellcheck="false" rows="22" />
    <div class="row">
      <button :disabled="busy" @click="validate">Validate</button>
      <button class="primary" :disabled="busy" @click="save">{{ saveLabel }}</button>
      <button class="ghost" @click="reset">Reset</button>
      <span v-if="status" class="ok-text">{{ status }}</span>
    </div>
    <ul v-if="errors.length" class="errors">
      <li v-for="(e, i) in errors" :key="i"><code>{{ e.path }}</code> {{ e.message }}</li>
    </ul>
  </div>
</template>
