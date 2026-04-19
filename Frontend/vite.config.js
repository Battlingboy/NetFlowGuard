import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    host: '0.0.0.0', // 使得局域网内可访问
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://【【】】',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://【【】】',
        ws: true,
        changeOrigin: true,
      }
    }
  }
})
