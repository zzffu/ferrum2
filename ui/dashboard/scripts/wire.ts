// Derive browser declarations from the dependency-free Rust wire contract.
// Intentionally supports only the concrete serde structs/enums used by that contract;
// unsupported syntax fails the build instead of silently widening the browser types.
import { readFile, writeFile } from "node:fs/promises";
const source = await readFile(
  new URL("../../../crates/ferrum2-dashboard/src/wire.rs", import.meta.url),
  "utf8",
);
const target = new URL("../src/wire.ts", import.meta.url);
const snake = (s: string) =>
  s.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
function type(s: string): string {
  s = s.trim();
  if (s === "String") return "string";
  if (s === "bool") return "boolean";
  if (/^(usize|u16|u32|f64)$/.test(s)) return "number";
  if (s === "serde_json::Value") return "unknown";
  const container = /^(Vec|Option)<(.+)>$/.exec(s);
  if (container)
    return container[1] === "Vec"
      ? `Array<${type(container[2]!)}>`
      : `${type(container[2]!)} | null`;
  if (/^[A-Z]\w*$/.test(s)) return s;
  throw new Error(`Unsupported Rust wire type: ${s}`);
}
function fields(body: string): string {
  return body
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((field) => {
      const match = /^(?:pub\s+)?(\w+)\s*:\s*(.+)$/.exec(field);
      if (!match) throw new Error(`Unsupported wire field: ${field}`);
      return `${match[1]}: ${type(match[2]!)};`;
    })
    .join(" ");
}
let output =
  "// Generated from crates/ferrum2-dashboard/src/wire.rs; run bun scripts/wire.ts.\n";
const declaration = /((?:#\[[^\n]+\]\s*)+)pub (enum|struct) (\w+)\s*\{/g;
for (let match; (match = declaration.exec(source));) {
  let end = declaration.lastIndex,
    depth = 1;
  for (; depth && end < source.length; end++) {
    if (source[end] === "{") depth++;
    else if (source[end] === "}") depth--;
  }
  if (depth) throw new Error("Unbalanced Rust declaration");
  const body = source.slice(declaration.lastIndex, end - 1);
  declaration.lastIndex = end;
  if (match[2] === "struct") {
    output += `export interface ${match[3]} { ${fields(body)} }\n`;
    continue;
  }
  const tag = /tag\s*=\s*"([^"]+)"/.exec(match[1]!)?.[1];
  const casing = /rename_all\s*=\s*"([^"]+)"/.exec(match[1]!)?.[1];
  const variants: string[] = [];
  let rest = body.trim();
  while (rest) {
    const variant =
      /^(?:#\[serde\(rename\s*=\s*"([^"]+)"\)\]\s*)?(\w+)\s*(?:\{([^{}]*)\})?\s*,?\s*/.exec(
        rest,
      );
    if (!variant) throw new Error(`Unsupported wire variant: ${rest}`);
    const name =
      variant[1] ??
      (casing === "snake_case"
        ? snake(variant[2]!)
        : casing === "lowercase"
          ? variant[2]!.toLowerCase()
          : variant[2]!);
    variants.push(
      tag
        ? `{ ${tag}: ${JSON.stringify(name)}; ${fields(variant[3] ?? "")} }`
        : JSON.stringify(name),
    );
    rest = rest.slice(variant[0].length);
  }
  output += `export type ${match[3]} =\n  ${variants.join(" |\n  ")};\n`;
}
if (process.argv.includes("--check")) {
  if ((await readFile(target, "utf8")) !== output)
    throw new Error(
      "Stale dashboard wire declarations; run bun scripts/wire.ts",
    );
} else await writeFile(target, output);
