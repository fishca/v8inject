// Regenerate src/payload/icons/*.png from the MIT-licensed Phosphor icon
// sources in src/payload/icons/phosphor/ (see ATTRIBUTION.md there).
//
// The icons are recoloured into the Configurator's palette with a vertical
// gradient (light top / dark bottom) and rasterised to 16x16; the committed
// PNGs are what tools/gen_icons.py bakes into icons.h and icons_png.h.
//
// One-time setup (needs network):   npm install --no-save sharp
// Run from the repository root:      node tools/render_icons.cjs
//
// sharp is a dev-only tool: builds and CI never run this script, they use the
// committed PNGs.

const fs = require("node:fs");
const path = require("node:path");
const sharp = require("sharp");

const ROOT = path.resolve(__dirname, "..");
const ICON_DIR = path.join(ROOT, "src", "payload", "icons");
const SRC_DIR = path.join(ICON_DIR, "phosphor");

// palette: light top stop, dark bottom stop (sampled from Configurator chrome)
const GREEN = ["#6FD07C", "#2E8B47"];
const BLUE = ["#7FA8E8", "#2F5CA8"];
const SYNC = ["#7FB6EC", "#255F9E"];
const TEAL = ["#68C9C0", "#1F7A73"];
const GOLD = ["#E8C46A", "#9A6E12"];
const BROWN = ["#D9A75C", "#8A5518"];
const GRAY = ["#C9C3B4", "#6E685B"];

// role -> [phosphor source, gradient]; glyphs were chosen by menu purpose
const ROLES = {
  dump: ["dump", GREEN],           // file + down arrow: dump config to files
  dumpext: ["dumpext", GREEN],     // puzzle: extension export
  init: ["init", BLUE],            // folder + plus: git init in dump dir
  clone: ["clone", BLUE],          // two sheets: copy of a repository
  commit: ["commit", GREEN],       // git commit node
  push: ["push", SYNC],            // arrow up: push
  pull: ["pull", SYNC],            // arrow down: pull
  fetch: ["fetch", TEAL],          // circular arrows: fetch
  branches: ["branches", BLUE],    // git branch graph
  stash: ["stash", GOLD],          // archive box: stash
  tags: ["tags", GOLD],            // tag: tags
  status: ["status", GREEN],       // checklist: working copy
  log: ["log", BROWN],             // history clock
  settings: ["settings", GRAY],    // gear
  gitbar: ["gitbar", BLUE],        // git fork mark for the GitBar item
};

function parts(file) {
  const text = fs.readFileSync(file, "utf8");
  const m = text.match(/<svg([^>]*)>([\s\S]*)<\/svg>/);
  if (!m) throw new Error("bad svg " + file);
  const vb = (m[1].match(/viewBox="([^"]+)"/) || [])[1] || "0 0 16 16";
  return { vb, body: m[2].replace(/\sfill="[^"]*"/g, "") };
}

function wrap({ vb, body }, [c0, c1]) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="${vb}">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="${c0}"/><stop offset="1" stop-color="${c1}"/>
</linearGradient></defs><g fill="url(#g)">${body}</g></svg>`;
}

async function main() {
  for (const [role, [src, cols]] of Object.entries(ROLES)) {
    const svg = wrap(parts(path.join(SRC_DIR, src + ".svg")), cols);
    const png = await sharp(Buffer.from(svg), { density: 384 })
      .resize(16, 16, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toBuffer();
    const out = path.join(ICON_DIR, role + ".png");
    fs.writeFileSync(out, png);
    console.log("wrote", path.relative(ROOT, out), png.length, "bytes");
  }
  console.log(`${Object.keys(ROLES).length} icons rendered from Phosphor sources`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
