/**
 * Extension build.
 *
 * Produces `dist/` — the directory Chrome loads unpacked and the payload that
 * `package.py` places at the root of the versioned Web Store ZIP.
 *
 * Deliberately plain esbuild rather than a framework plugin: the output has to
 * be auditable against the published source (see README), and a build a
 * reviewer can read end to end is worth more here than a shorter config.
 *
 * Determinism matters — a reproducible build is the thing that lets a customer
 * verify the uploaded ZIP matches this repository. No timestamps, no build
 * IDs, no absolute paths in the output.
 */

import { build } from "esbuild";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
  // Complete project and third-party licence texts are copied into dist below.
  // Keeping them as standalone deterministic files avoids duplicating stripped
  // banners throughout the readable bundle while preserving every notice.
  legalComments: "none",
  logLevel: "warning",
  // The UI entry point lives in the sibling frontend source tree. Resolve its
  // runtime imports from this package so a clean extension checkout/build does
  // not accidentally depend on frontend/node_modules being present.
  nodePaths: [join(root, "node_modules")],
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
  // Keep the bundle readable without accidentally shipping React's much
  // larger development runtime. Esbuild otherwise selects development when
  // minification is intentionally disabled for source review.
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  // Package resolution normally starts beside the imported frontend source,
  // which would make an unrelated frontend/node_modules silently affect the
  // extension bundle. Alias the two runtime packages to this locked package.
  alias: {
    react: join(root, "node_modules/react"),
    "react-dom": join(root, "node_modules/react-dom"),
  },
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

const uiBundle = await readFile(join(dist, "src/ui/app.js"), "utf8");
if (/react(?:-dom)?(?:-client)?\.development\.js/.test(uiBundle)) {
  throw new Error("The extension UI bundle contains a React development runtime");
}

async function copyTextWithLf(source, destination) {
  const contents = await readFile(source, "utf8");
  await writeFile(destination, contents.replace(/\r\n?/g, "\n"), "utf8");
}

function withLf(contents) {
  return contents.replace(/\r\n?/g, "\n");
}

const repositoryRoot = join(root, "..", "..");
const projectLicense = withLf(await readFile(join(repositoryRoot, "LICENSE"), "utf8"));
if (!/^\s*Apache License\n\s*Version 2\.0, January 2004/m.test(projectLicense)) {
  throw new Error("The repository LICENSE is not the reviewed Apache-2.0 text");
}
const repositoryReadme = withLf(await readFile(join(repositoryRoot, "README.md"), "utf8"));
if (!/repository is licensed under the Apache License 2\.0/i.test(repositoryReadme)) {
  throw new Error("README licence declaration does not match the Apache-2.0 LICENSE");
}

const thirdPartyNotices = withLf(await readFile(join(root, "THIRD_PARTY_NOTICES"), "utf8"));
const bundledPackages = new Map([
  ["react", "19.2.8"],
  ["react-dom", "19.2.8"],
  ["scheduler", "0.27.0"],
]);
const bundledLicenseTexts = new Set();
for (const [packageName, expectedVersion] of bundledPackages) {
  const packageDirectory = join(root, "node_modules", packageName);
  const packageMetadata = JSON.parse(
    await readFile(join(packageDirectory, "package.json"), "utf8"),
  );
  if (packageMetadata.version !== expectedVersion || packageMetadata.license !== "MIT") {
    throw new Error(
      `${packageName} licence/version drifted: expected MIT ${expectedVersion}`,
    );
  }
  if (!thirdPartyNotices.includes(`${packageName} ${expectedVersion} (MIT)`)) {
    throw new Error(`THIRD_PARTY_NOTICES does not identify ${packageName} ${expectedVersion}`);
  }
  bundledLicenseTexts.add(
    withLf(await readFile(join(packageDirectory, "LICENSE"), "utf8")).trim(),
  );
}
if (
  bundledLicenseTexts.size !== 1 ||
  !thirdPartyNotices.includes([...bundledLicenseTexts][0]) ||
  !thirdPartyNotices.includes("Modernizr 3.0.0pre (Custom Build) | MIT")
) {
  throw new Error("THIRD_PARTY_NOTICES does not preserve the bundled MIT notices");
}

// Git may check text files out with CRLF on Windows. Normalize the two copied
// text inputs explicitly so the same source produces the same payload bytes on
// every supported build host.
await copyTextWithLf(join(root, "manifest.json"), join(dist, "manifest.json"));
await copyTextWithLf(join(root, "src/ui/index.html"), join(dist, "src/ui/index.html"));
await copyTextWithLf(join(repositoryRoot, "LICENSE"), join(dist, "LICENSE"));
await copyTextWithLf(
  join(root, "THIRD_PARTY_NOTICES"),
  join(dist, "THIRD_PARTY_NOTICES"),
);
await mkdir(join(dist, "icons"), { recursive: true });
for (const icon of ["icon-16.png", "icon-32.png", "icon-48.png", "icon-128.png"]) {
  await cp(join(root, "icons", icon), join(dist, "icons", icon));
}

// Record every payload file so a verifier can compare the uploaded archive
// without trusting a hand-maintained allowlist. SHA256SUMS.json is the only
// exclusion because a digest manifest cannot contain its own digest.
async function listPayloadFiles(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      files.push(...await listPayloadFiles(join(directory, entry.name), relative));
    } else if (relative !== "SHA256SUMS.json") {
      files.push(relative);
    }
  }
  return files;
}

const files = (await listPayloadFiles(dist)).sort();
for (const requiredLegalFile of ["LICENSE", "THIRD_PARTY_NOTICES"]) {
  if (!files.includes(requiredLegalFile)) {
    throw new Error(`The distributable is missing ${requiredLegalFile}`);
  }
}
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
