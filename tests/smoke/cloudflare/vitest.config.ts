import { defineConfig, mergeConfig } from "vitest/config";
import rootConfig from "../../../vitest.config.js";

export default mergeConfig(
  rootConfig,
  defineConfig({
    test: {
      environment: "miniflare",
      environmentOptions: {
        modules: true,
        scriptPath: "tests/smoke/cloudflare/cloudflare.test.ts",
        bindings: {
          CF_WORKER: true,
        },
      },
      include: ["tests/smoke/cloudflare/**/*.test.ts"],
    },
  }),
);
