import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
  // Output ESM only - better-auth is ESM-only, so CJS output won't work
  rollup: {
    emitCJS: false,
    esbuild: {
      tsconfigRaw: {
        compilerOptions: {
          experimentalDecorators: true,
        },
      },
    },
  },
});
