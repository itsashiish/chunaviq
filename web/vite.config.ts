import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const buildId = process.env.VERCEL_GIT_COMMIT_SHA ?? "local";

export default defineConfig({
  plugins: [react()],
  define: { "globalThis.__BUILD_ID__": JSON.stringify(buildId) },
  worker: { format: "es" },
  build: { target: "es2022", sourcemap: false },
  test: { environment: "node", testTimeout: 600_000, include: ["tests/**/*.test.{ts,tsx}"] },
});
