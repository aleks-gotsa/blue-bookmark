// Copies node icons (svg/png) next to the compiled .node.js files.
const fs = require("fs");
const path = require("path");
const src = path.join(__dirname, "..", "nodes");
const dst = path.join(__dirname, "..", "dist", "nodes");
function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.(svg|png)$/i.test(e.name)) {
      const out = path.join(dst, path.relative(src, p));
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.copyFileSync(p, out);
      console.log("copied", path.relative(process.cwd(), out));
    }
  }
}
walk(src);
