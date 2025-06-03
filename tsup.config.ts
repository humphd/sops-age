import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm"],
    dts: true,
    minify: false,
    clean: true,
    outDir: "dist",
    sourcemap: true,
    treeshake: true,
    metafile: true,
    removeNodeProtocol: false,
  },
  // CJS build - bundle ESM-only deps
  {
    entry: ["src/index.ts"],
    format: ["cjs"],
    // The age-encryption lib is ESM-only, so pull it in for CJS
    noExternal: ["age-encryption"],
    minify: false,
    outDir: "dist",
    sourcemap: true,
    metafile: true,
    splitting: true,
    treeshake: true,
  },
  // IIFE build
  {
    entry: ["src/index.ts"],
    format: ["iife"],
    globalName: "decryptSops",
    minify: true,
    outDir: "dist",
    sourcemap: true,
    treeshake: true,
    metafile: true,
  },
]);
