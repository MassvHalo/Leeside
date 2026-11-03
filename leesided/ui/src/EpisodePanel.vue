<template>
  <div class="workspace">
    <section class="episodes" aria-label="Attacks">
      <template v-for="g in groups" :key="g.state">
        <h2 class="episodes-heading">{{ g.heading }}</h2>
        <p v-if="g.items.length === 0" class="episodes-none">{{ noneWord }}</p>
        <ul v-else class="episode-list">
          <li v-for="e in g.items" :key="e.id" class="episode-row">
            <button
              type="button"
              class="episode"
              :class="{ 'is-done': done.has(e.id) }"
              :aria-current="e.id === selectedId ? 'true' : null"
              @click="$emit('select', e.id)"
            >
              <span class="glyph" data-field="episode.state" :data-state="e.state">{{ e.state }}</span>
              <span class="episode-text"><span class="episode-title" data-field="episode.title">{{ e.title }}</span><time class="time episode-span" data-field="episode.span">{{ fmtSpan(e.span_start, e.span_end, nowS, windowS) }}</time></span>
              <span class="episode-done">done</span>
              <span data-field="episode.id" hidden>{{ e.id }}</span>
            </button>
          </li>
        </ul>
      </template>
    </section>
    <section v-if="!selected" class="detail detail-empty" aria-label="This attack">
      <h2 class="detail-title">Nothing to look at yet.</h2>
      <p class="detail-summary">Windside is learning what normal looks like here. Anything hostile will show up in this space with the full story.</p>
    </section>
    <section v-else class="detail" aria-label="This attack" aria-live="polite">
      <header class="detail-head">
        <div class="detail-state"><span class="glyph" data-field="episode.state" :data-state="selected.state">{{ selected.state }}</span><span>{{ stateWord(selected.state) }}</span><time class="time" data-field="episode.span">{{ fmtSpan(selected.span_start, selected.span_end, nowS, windowS) }}</time><span data-field="episode.id" hidden>{{ selected.id }}</span></div>
        <h2 class="detail-title" data-field="episode.title">{{ selected.title }}</h2>
        <p class="detail-summary" data-field="episode.summary">{{ selected.summary }}</p>
        <p v-if="selected.explained_by" class="explained-tag">explained by <span data-field="episode.explained_by">{{ selected.explained_by }}</span></p>
      </header>
      <ol class="story">
        <li class="story-step"><span class="step-label">Who came</span><p class="step-text" data-field="episode.story.who">{{ selected.story.who }}</p></li>
        <li class="story-step"><span class="step-label">What they tried</span><p class="step-text" data-field="episode.story.what">{{ selected.story.what }}</p></li>
        <li class="story-step"><span class="step-label">What Leeside did</span><p class="step-text" data-field="episode.story.did">{{ selected.story.did }}</p></li>
        <li class="story-step story-step-next"><span class="step-label">What's next</span>
          <div v-if="selected.state === 'waiting' && canDecide" class="decisions" role="group" aria-label="Your decision">
            <button type="button" class="decision" data-action="confirm" @click="$emit('decide', 'confirm')">It's an attack<kbd>1</kbd></button>
            <button type="button" class="decision" data-action="benign" @click="$emit('decide', 'benign')">It's fine<kbd>2</kbd></button>
            <button type="button" class="decision" data-action="unknown" @click="$emit('decide', 'unknown')">Not sure<kbd>3</kbd></button>
          </div>
          <p v-if="selected.state === 'waiting'" class="evidence" data-field="episode.story.next">{{ selected.story.next }}</p>
          <p v-else class="step-text" data-field="episode.story.next">{{ selected.story.next }}</p>
        </li>
      </ol>
      <div class="closer">
        <span class="closer-label">Look closer</span>
        <a v-for="c in selected.chips" :key="c.href" class="chip" data-field="chip.href" :href="c.href"><span v-if="c.count !== null && c.count !== undefined" class="chip-count" data-field="chip.count">{{ fmtInt(c.count) }}</span><span data-field="chip.label">{{ c.label }}</span><svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></a>
      </div>
      <div class="detail-foot"><button type="button" class="next-button" @click="$emit('next', 1)">Next<svg class="arrow" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M3.5 2 L6.5 5 L3.5 8"></path></svg></button><span class="key-hint"><kbd>j</kbd><kbd>k</kbd> move</span></div>
    </section>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtInt, fmtSpan } from './fmt.js'

const props = defineProps({
  episodes: { type: Array, required: true },
  selectedId: { type: String, default: null },
  done: { type: Set, required: true },
  canDecide: { type: Boolean, required: true },
  nowS: { type: Number, required: true },
  windowS: { type: Number, required: true },
})

defineEmits(['select', 'next', 'decide'])

const headings = { stopped: 'Stopped', waiting: 'Waiting on you', watched: 'Watched' }

const groups = computed(() => {
  const by = { stopped: [], waiting: [], watched: [] }
  for (const e of props.episodes) (by[e.state] || by.watched).push(e)
  return ['stopped', 'waiting', 'watched'].map((state) => ({
    state,
    heading: headings[state],
    items: by[state],
  }))
})

const noneWord = computed(() => (props.episodes.length === 0 ? 'None yet' : 'Nothing here'))

const selected = computed(() => props.episodes.find((e) => e.id === props.selectedId) || null)

function stateWord(state) {
  return { stopped: 'Stopped', waiting: 'Waiting on you', watched: 'Watched' }[state] || state
}
</script>
