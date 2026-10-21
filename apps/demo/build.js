// Builds apps/demo/dist/index.html: one self-contained file with the core IIFE bundle inlined.
// Usage: node apps/demo/build.js   (run after `npm run build -w @blue-bookmark/core`)
const fs = require("fs");
const path = require("path");

const here = __dirname;
const src = path.join(here, "index.html");
const core = path.join(here, "..", "..", "packages", "core", "dist", "blue-bookmark.iife.js");
const outDir = path.join(here, "dist");
const out = path.join(outDir, "index.html");

if (!fs.existsSync(core)) {
  console.error("core bundle missing: build @blue-bookmark/core first (npm run build -w @blue-bookmark/core)");
  process.exit(1);
}
let html = fs.readFileSync(src, "utf8");
const js = fs.readFileSync(core, "utf8").replace(/<\/script/gi, "<\\/script");
const marker = /<!-- BLUE_BOOKMARK_CORE -->\s*<script src="\.\.\/\.\.\/packages\/core\/dist\/blue-bookmark\.iife\.js"><\/script>/;
if (!marker.test(html)) {
  console.error("marker not found in apps/demo/index.html");
  process.exit(1);
}
html = html.replace(marker, () => `<script>/* @blue-bookmark/core, inlined at build time */\n${js}\n</script>`);
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(out, html);
const kb = (fs.statSync(out).size / 1024).toFixed(1);
console.log(`wrote ${path.relative(process.cwd(), out)} (${kb} KB)`);
