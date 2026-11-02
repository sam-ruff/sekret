import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const backend = "http://localhost:8080";

export default defineConfig({
  base: "/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "src") },
  },
  server: {
    port: 5173,
    // Compiles the app and the mock up front, so the first pages a test opens do not time out.
    warmup: { clientFiles: ["./src/main.tsx", "./src/api/mock/*.ts"] },
    // Test reports and traces are written while tests run; watching them reloads every open page,
    // which drops the mock's state partway through a test.
    watch: {
      ignored: ["**/test-results/**", "**/playwright-report*/**", "**/dist/**", "**/tests-live/.auth/**"],
    },
    proxy: {
      "/api": { target: backend, changeOrigin: false },
      "/auth": { target: backend, changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // The zxcvbn dictionaries are one large chunk, loaded only on passphrase forms.
    chunkSizeWarningLimit: 1300,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
  },
});
