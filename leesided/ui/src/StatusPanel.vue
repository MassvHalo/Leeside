<template>
  <header v-if="!status" class="page-head" aria-busy="true">
    <div class="page-head-text">
      <p class="crumb">Settings <span aria-hidden="true">&rsaquo;</span> <b>Status</b></p>
      <span class="skeleton skeleton-title"></span>
    </div>
  </header>
  <header v-else class="page-head">
    <div class="page-head-text">
      <p class="crumb">Settings <span aria-hidden="true">&rsaquo;</span> <b>Status</b></p>
      <div class="headline-row"><h1 class="headline">Status</h1></div>
      <p class="subline">Settings live in /etc/leeside/leesided.env on the box; restart leesided after a change.</p>
    </div>
  </header>

  <div v-if="!status" class="panels">
    <section v-for="n in 5" :key="n" class="panel" aria-busy="true">
      <span class="skeleton skeleton-line skeleton-short"></span>
      <span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line"></span>
    </section>
  </div>

  <div v-else class="panels">
    <section class="panel" aria-label="Protection">
      <h3 class="panel-title">Protection</h3>
      <dl class="facts">
        <div><dt>Windside mode</dt><dd data-field="status.protection.windside">{{ status.windside.mode }}</dd></div>
        <div><dt>Enforce allowed</dt><dd data-field="status.protection.enforce">{{ status.enforce_allowed ? 'yes' : 'no' }}</dd></div>
        <div><dt>Rules loaded</dt><dd data-field="status.protection.rules">{{ fmtInt(status.rules.loaded) }}</dd></div>
        <div><dt>Ruleset hash</dt><dd class="mono-cell" data-field="status.protection.hash">{{ status.rules.hash }}</dd></div>
        <div><dt>Decisions active</dt><dd data-field="status.protection.decisions">{{ fmtInt(status.decisions) }}</dd></div>
      </dl>
    </section>

    <section class="panel" aria-label="Model">
      <h3 class="panel-title">Model</h3>
      <dl class="facts">
        <div><dt>Model version</dt><dd data-field="status.model.version">{{ status.windside.model_version || 'none loaded' }}</dd></div>
        <div><dt>Features version</dt><dd data-field="status.model.features">{{ status.windside.features_version === null || status.windside.features_version === undefined ? '—' : status.windside.features_version }}</dd></div>
        <div><dt>Scored</dt><dd data-field="status.model.scored">{{ fmtInt(status.windside.scored.actor) }} actors · {{ fmtInt(status.windside.scored.cluster) }} clusters</dd></div>
      </dl>
    </section>

    <section class="panel" aria-label="Assistant">
      <h3 class="panel-title">Assistant</h3>
      <dl class="facts">
        <div><dt>Mode</dt><dd data-field="status.assistant.mode">{{ status.llm.mode }}</dd></div>
        <div><dt>Model</dt><dd data-field="status.assistant.model">{{ assistantModel || '—' }}</dd></div>
      </dl>
    </section>

    <section class="panel" aria-label="Identity">
      <h3 class="panel-title">Identity</h3>
      <dl class="facts">
        <div><dt>IP hashing</dt><dd data-field="status.identity.hashing">{{ status.ip_hashing ? 'on' : 'off' }}</dd></div>
        <div><dt>JA4 classes</dt><dd data-field="status.identity.ja4">{{ fmtInt(status.ja4_classes) }} loaded</dd></div>
        <div><dt>Tap</dt><dd data-field="status.identity.tap">{{ tapLine }}</dd></div>
        <div><dt>GeoIP databases</dt><dd data-field="status.identity.geoip">{{ status.geoip ? 'present' : 'absent' }}</dd></div>
      </dl>
    </section>

    <section class="panel" aria-label="Store">
      <h3 class="panel-title">Store</h3>
      <dl class="facts">
        <div><dt>Migration</dt><dd data-field="status.store.migration">{{ fmtInt(status.migration_version) }}</dd></div>
        <div><dt>Uptime</dt><dd data-field="status.store.uptime">{{ fmtDur(status.uptime_s) }}</dd></div>
        <div><dt>Actors</dt><dd data-field="status.store.actors">{{ fmtInt(status.actors.count) }}</dd></div>
        <div><dt>Clusters</dt><dd data-field="status.store.clusters">{{ fmtInt(status.windows.clusters) }}</dd></div>
        <div><dt>Sessions</dt><dd data-field="status.store.sessions">{{ fmtInt(status.windows.sessions) }}</dd></div>
      </dl>
    </section>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtDur, fmtInt } from './fmt.js'

const props = defineProps({
  status: { type: Object, default: null },
  assistantModel: { type: String, default: null },
})

const tapLine = computed(() => {
  if (!props.status) return ''
  const t = props.status.tap
  if (!t || t.messages === 0) return 'quiet — no messages yet'
  return `receiving — ${fmtInt(t.messages)} messages, ${fmtInt(t.matched)} matched`
})
</script>
