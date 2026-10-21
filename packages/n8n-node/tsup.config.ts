import { defineConfig } from "tsup";

// The core is bundled into the node file: n8n does not allow verified community nodes to have runtime dependencies.
// n8n-workflow is provided by n8n itself and stays external.
export default defineConfig({
  entry: { "nodes/BlueBookmark/BlueBookmark.node": "nodes/BlueBookmark/BlueBookmark.node.ts" },
  outDir: "dist",
  format: ["cjs"],
  target: "es2020",
  platform: "node",
  noExternal: ["@blue-bookmark/core"],
  external: ["n8n-workflow"],
  sourcemap: true,
  clean: true,
  dts: false,
});
