import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:1420",
      "/previews": "http://127.0.0.1:1420"
    }
  },
  build: {
    outDir: "dist",
    emptyOutDir: true
  }
});
