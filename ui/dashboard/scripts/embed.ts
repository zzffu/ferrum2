import { createHash } from "node:crypto";
import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

if (Bun.version !== "1.4.2")
  throw new Error("Use the pinned Bun 1.4.2 toolchain");
const root = fileURLToPath(new URL("../", import.meta.url));
const files = await readdir(`${root}/dist`, { recursive: true });
if (files.length !== 1 || files[0] !== "index.html")
  throw new Error("Build must produce exactly dist/index.html");
const html = await readFile(`${root}/dist/index.html`, "utf8");
// Parse markup rather than searching bundled JavaScript for strings such as "<link".
await new HTMLRewriter()
  .on("*", {
    element(element) {
      if (element.tagName === "link")
        throw new Error("External link resources are forbidden");
      for (const [name, value] of element.attributes) {
        if (
          name.startsWith("on") ||
          name === "srcset" ||
          (name === "src" && !value.startsWith("data:")) ||
          (element.tagName === "object" && name === "data")
        ) {
          throw new Error(
            `External resource or inline handler: ${element.tagName}.${name}`,
          );
        }
      }
    },
  })
  .transform(new Response(html))
  .text();
const scriptBodies = [
  ...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi),
].map((m) => m[1]);
const styleBodies = [
  ...html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi),
].map((m) => m[1]);
if (
  styleBodies.some((css) => /@import\s|url\(\s*['"]?(?!data:|#)/i.test(css))
) {
  throw new Error("External styles or fonts are forbidden");
}
const hash = (text: string) =>
  `'sha256-${createHash("sha256").update(text).digest("base64")}'`;
const scripts = scriptBodies.map(hash);
const styles = styleBodies.map(hash);
if (!scripts.length || !styles.length)
  throw new Error("Expected inline application script and styles");
const csp = `default-src 'none'; script-src ${[...new Set(scripts)].join(" ")}; style-src ${[...new Set(styles)].join(" ")}; connect-src 'self'; img-src data:; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`;
const metadata =
  JSON.stringify(
    {
      schema: 1,
      package: "@ferrum2/dashboard",
      version: "0.1.0",
      bun: Bun.version,
      sha256: createHash("sha256").update(html).digest("hex"),
    },
    null,
    2,
  ) + "\n";
const outputs = { "index.html": html, "csp.txt": csp, "build.json": metadata };
if (process.argv.includes("--check")) {
  for (const [name, expected] of Object.entries(outputs)) {
    if ((await readFile(`${root}/embedded/${name}`, "utf8")) !== expected)
      throw new Error(`Stale shipping asset: ${name}. Run bun run build.`);
  }
  console.log(
    "Shipping HTML, CSP and build identity match the locked source build.",
  );
} else {
  await mkdir(`${root}/embedded`, { recursive: true });
  for (const [name, content] of Object.entries(outputs))
    await writeFile(`${root}/embedded/${name}`, content);
  console.log(
    "Embedded one self-contained HTML document with deterministic CSP hashes.",
  );
}
