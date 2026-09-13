import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The unit tests of the panel: components rendered in jsdom, hooks with a
// fake localStorage, and the translation catalogue checked against the
// strings the screens actually use. The browser tests live in e2e/ and run
// under Playwright, so they are kept out of this runner.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    exclude: ["node_modules", "dist", "e2e"],
    // Keeps the DOM of one test out of the next; the library's automatic
    // cleanup hooks into afterEach only when it is a global.
    globals: true,
    css: false,
  },
});
