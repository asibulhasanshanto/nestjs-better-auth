import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  // Bundle better-auth into output to avoid ESM/CJS issues
  // This inlines the better-auth/node and better-auth/plugins code
  noExternal: [/^better-auth/],
  esbuildOptions(options) {
    options.keepNames = true;
  },
  // Ensure decorators work
  target: "node18",
});
