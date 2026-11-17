import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const BACKEND = process.env.TUNNELGATE_DEV_BACKEND ?? 'http://127.0.0.1:8080'

// The dev server mirrors what nginx does in production: /api and /__tg go to the panel,
// everything else is the SPA. `ws: true` keeps the console WebSocket usable in dev.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: BACKEND, changeOrigin: false, ws: true },
      '/__tg': { target: BACKEND, changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    target: 'es2020',
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: {
          // xterm is only needed by /routers/:id/console; keep it out of the first paint.
          xterm: ['@xterm/xterm', '@xterm/addon-fit', '@xterm/addon-web-links'],
        },
      },
    },
  },
})
