import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "es2020",
  },
  {
    entry: { "blue-bookmark": "src/index.ts" },
    format: ["iife"],
    globalName: "BlueBookmark",
    outExtension: () => ({ js: ".iife.js" }),
    minify: true,
    target: "es2020",
    sourcemap: false,
  },
]);
