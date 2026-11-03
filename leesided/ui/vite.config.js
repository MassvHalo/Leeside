import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Relative asset URLs: the dashboard is served from the console
// prefix (/windside/), which varies per install.
export default defineConfig({
  base: './',
  plugins: [vue()],
})
