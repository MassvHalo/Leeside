import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// In production nginx serves dist/ and proxies /api/ to leesided. In dev,
// point LEESIDED_API at a running daemon (default: the e2e port).
const api = process.env.LEESIDED_API || 'http://127.0.0.1:7391'

export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      '/api': { target: api, rewrite: (p) => p.replace(/^\/api/, '') },
    },
  },
})
