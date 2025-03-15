import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
    coverage: {
      all: true,
      exclude: ["dist", "tests/smoke"],
      include: ["tests/unit"],
      reporter: ["html", "lcov"],
    },
    env: {
      SOPS_AGE_KEY:
        "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P",
    },
    include: ["tests/unit/**/*.test.ts"],
    exclude: ["dist", "node_modules"],
    setupFiles: ["console-fail-test/setup"],
  },
});
