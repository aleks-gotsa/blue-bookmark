// Fails the build when the compiled node still needs a runtime dependency: n8n does not allow verified community
// nodes to have any, so the core is bundled into the node file and only n8n-workflow (provided by n8n) stays external.
const fs = require("fs");
const path = require("path");
const pkg = require("../package.json");
const file = path.join(__dirname, "..", pkg.n8n.nodes[0]);
const code = fs.readFileSync(file, "utf8");
const needs = [...code.matchAll(/require\(["']([^"'.][^"']*)["']\)/g)].map((m) => m[1]).filter((m) => m !== "n8n-workflow" && !m.startsWith("node:"));
const deps = Object.keys(pkg.dependencies ?? {});
if (needs.length || deps.length) {
  console.error(`runtime dependencies left: requires [${needs.join(", ")}], dependencies [${deps.join(", ")}]`);
  process.exit(1);
}
console.log(`bundle ok: ${path.relative(process.cwd(), file)} needs only n8n-workflow`);
