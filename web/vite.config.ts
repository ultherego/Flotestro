import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Panel jest serwowany przez control plane pod tym samym adresem co API,
// wiec ciasteczko sesji dziala bez konfiguracji CORS.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/api": "http://192.168.56.10:8080",
      "/auth": "http://192.168.56.10:8080",
      "/healthz": "http://192.168.56.10:8080",
    },
  },
});
