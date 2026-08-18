/**
 * Extension build.
 *
 * Produces `dist/` — the directory Chrome loads unpacked, the ZIP uploaded to
 * the Web Store, and the payload of the self-hosted CRX. One build serves all
 * three so there is no chance of them differing.
 *
 * Deliberately plain esbuild rather than a framework plugin: the output has to
 * be auditable against the published source (see README), and a build a
 * reviewer can read end to end is worth more here than a shorter config.
 *
 * Determinism matters — a reproducible build is the thing that lets a customer
 * verify the published CRX matches this repository. No timestamps, no build
 * IDs, no absolute paths in the output.
 */

import { build } from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });

const shared = {
  bundle: true,
  format: "esm",
  target: "chrome142",
  platform: "browser",
  // Sourcemaps embed absolute paths and defeat byte-for-byte reproducibility.
  sourcemap: false,
  legalComments: "none",
  logLevel: "warning",
};

await build({
  ...shared,
  entryPoints: [join(root, "src/background/service-worker.ts")],
  outfile: join(dist, "src/background/service-worker.js"),
  // The worker is the only privileged context; keeping it unminified means a
  // reviewer can read exactly what talks to Google.
  minify: false,
});

// The React wizard, built from the shared frontend sources with one module
// swapped: `lib/transport` resolves to the extension's message-based
// implementation instead of the HTTP one. Everything above that file --
// `api.ts` and every component -- is byte-identical between the two builds.
await build({
  ...shared,
  entryPoints: [join(root, "../frontend/src/main.tsx")],
  outfile: join(dist, "src/ui/app.js"),
  jsx: "automatic",
  loader: { ".tsx": "tsx", ".ts": "ts" },
  plugins: [
    {
      name: "extension-transport",
      setup(pluginBuild) {
        pluginBuild.onResolve({ filter: /(^|\/)lib\/transport$/ }, () => ({
          path: join(root, "src/ui/transport.ts"),
        }));
        pluginBuild.onResolve({ filter: /^\.\/transport$/ }, (args) =>
          args.importer.includes("frontend")
            ? { path: join(root, "src/ui/transport.ts") }
            : undefined,
        );
      },
    },
  ],
  minify: false,
});

await build({
  ...shared,
  entryPoints: [join(root, "src/ui/main.ts")],
  outfile: join(dist, "src/ui/main.js"),
  minify: false,
});

await cp(join(root, "manifest.json"), join(dist, "manifest.json"));
await cp(join(root, "src/ui/index.html"), join(dist, "src/ui/index.html"));
await cp(join(root, "src/ui/diagnostics.html"), join(dist, "src/ui/diagnostics.html"));
await cp(join(root, "src/ui/main.css"), join(dist, "src/ui/main.css"));
await cp(join(root, "icons"), join(dist, "icons"), { recursive: true });

// Record what was built so a verifier can compare without re-running the build.
const files = [
  "manifest.json",
  "src/background/service-worker.js",
  "src/ui/main.js",
  "src/ui/app.js",
  "src/ui/index.html",
  "src/ui/diagnostics.html",
  "src/ui/app.css",
  "src/ui/main.css",
  "icons/icon-16.png",
  "icons/icon-32.png",
  "icons/icon-48.png",
  "icons/icon-128.png",
];
const digests = {};
for (const file of files) {
  digests[file] = createHash("sha256").update(await readFile(join(dist, file))).digest("hex");
}
await writeFile(
  join(dist, "SHA256SUMS.json"),
  `${JSON.stringify(digests, Object.keys(digests).sort(), 2)}\n`,
  "utf8",
);

console.log("built dist/");
for (const [file, digest] of Object.entries(digests)) {
  console.log(`  ${digest.slice(0, 16)}  ${file}`);
}
