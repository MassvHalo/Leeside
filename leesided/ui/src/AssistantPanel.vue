<template>
  <header v-if="!assistant" class="page-head" aria-busy="true">
    <div class="page-head-text">
      <p class="crumb">Settings <span aria-hidden="true">&rsaquo;</span> <b>Assistant</b></p>
      <span class="skeleton skeleton-title"></span>
    </div>
  </header>
  <header v-else class="page-head">
    <div class="page-head-text">
      <p class="crumb">Settings <span aria-hidden="true">&rsaquo;</span> <b>Assistant</b></p>
      <div class="headline-row"><h1 class="headline">Assistant</h1></div>
      <p class="subline">It drafts proposals and explanations. Models run async, off a queue, never on the request path.</p>
    </div>
  </header>

  <div v-if="!assistant" class="panels">
    <section class="panel" aria-busy="true">
      <span class="skeleton skeleton-line skeleton-short"></span>
      <span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line"></span>
    </section>
  </div>

  <div v-else-if="!isOperator" class="panels">
    <section class="panel" aria-label="Model">
      <h3 class="panel-title">Model</h3>
      <p class="panel-sentence">Settings needs an operator session.</p>
    </section>
  </div>

  <div v-else class="panels">
    <section class="panel" aria-label="Model">
      <h3 class="panel-title">Model</h3>
      <dl class="facts">
        <div><dt>Model</dt><dd data-field="assistant.model">{{ assistant.model }}</dd></div>
        <div><dt>Mode</dt><dd data-field="assistant.mode">{{ assistant.mode }} — {{ modeGloss }}</dd></div>
      </dl>
      <p class="panel-sentence">Built with Muse Spark Open.</p>
    </section>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  assistant: { type: Object, default: null },
  isOperator: { type: Boolean, required: true },
})

const modeGloss = computed(() => {
  if (!props.assistant) return ''
  if (props.assistant.mode === 'live') return 'requests go out'
  if (props.assistant.mode === 'dry') return 'requests are built but never sent'
  return 'the assistant is disabled'
})
</script>
