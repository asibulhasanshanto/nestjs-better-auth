import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  // Bundle ESM dependencies into CJS output
  noExternal: ["better-auth"],
  esbuildOptions(options) {
    options.keepNames = true;
  },
});
