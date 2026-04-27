import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Proxy all /api/* requests to FastAPI backend
      '/api': {
        target: 'http://localhost:9000',
        changeOrigin: true
      },
      // Proxy WebSocket connection
      '/ws': {
        target: 'ws://localhost:9000',
        ws: true
      }
    }
  }
})
