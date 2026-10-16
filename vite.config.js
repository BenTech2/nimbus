import { defineConfig } from 'vite';

// Tauri expects a fixed dev port and a static build in ../dist.
export default defineConfig({
  clearScreen: false,
  server: { port: 1420, strictPort: true, watch: { ignored: ['**/src-tauri/**'] } },
  build: { target: 'es2022', outDir: 'dist', emptyOutDir: true },
});
