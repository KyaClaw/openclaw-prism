import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const fromRoot = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@kyaclaw\/shared\/heuristics$/, replacement: fromRoot("./packages/shared/src/heuristics.ts") },
      { find: /^@kyaclaw\/shared\/audit$/, replacement: fromRoot("./packages/shared/src/audit.ts") },
      { find: /^@kyaclaw\/shared\/types$/, replacement: fromRoot("./packages/shared/src/types.ts") },
      { find: /^@kyaclaw\/shared$/, replacement: fromRoot("./packages/shared/src/index.ts") },
    ],
  },
  test: {
    globals: true,
    include: ["packages/*/src/**/*.test.ts"],
  },
});
