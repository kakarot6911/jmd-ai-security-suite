import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Builds to ../web-dist, which FastAPI mounts at "/". Assets are self-hosted with
// relative paths, so the API's strict CSP (script-src 'self') is satisfied without
// needing a CDN exemption or an inline-script allowance.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  build: {
    outDir: "../web-dist",
    emptyOutDir: true,
    target: "es2020",
    rollupOptions: {
      output: {
        // Split React out of the app chunk so it caches independently of our
        // code. Rolldown (Vite 8) requires the function form, not an object map.
        manualChunks(id) {
          if (/node_modules[/\\](react|react-dom|scheduler)[/\\]/.test(id)) return "vendor";
          return undefined;
        },
      },
    },
  },
});
