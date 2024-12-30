import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm"],
    dts: true,
    minify: true,
    clean: true,
    outDir: "dist",
    sourcemap: true,
  },
  // CJS build - bundle ESM-only deps
  {
    entry: ["src/index.ts"],
    format: ["cjs"],
    // The age-encryption lib is ESM-only, so pull it in for CJS
    noExternal: ["age-encryption"],
    minify: true,
    outDir: "dist",
    sourcemap: true,
  },
  // IIFE build
  {
    entry: ["src/index.ts"],
    format: ["iife"],
    globalName: "decryptSops",
    minify: true,
    outDir: "dist",
    sourcemap: true,
  },
]);
