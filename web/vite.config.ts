import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The panel is served by the control plane at the same address as the API,
// so the session cookie works without any CORS configuration.
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
