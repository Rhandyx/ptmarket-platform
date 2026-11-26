// Gera o schema para um ficheiro temporário e compara com src/lib/api/schema.d.ts.
// Uso: node scripts/check-api.mjs [caminho/openapi.json]
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");

// --chunks: depois do build, nenhum chunk público pode conter os nomes das variáveis de servidor.
if (process.argv[2] === "--chunks") {
  const bad = [];
  const walk = (d) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) walk(p);
      else if (/INTERNAL_PROXY_TOKEN|API_INTERNAL_URL/.test(readFileSync(p, "utf8"))) bad.push(p);
    }
  };
  walk(join(root, ".next/static"));
  if (bad.length) {
    console.error("variável de servidor em chunk público:", bad.join(", "));
    process.exit(1);
  }
  process.exit(0);
}
const spec = resolve(process.argv[2] ?? join(root, "../backend-rust/openapi.json"));
const target = join(root, "src/lib/api/schema.d.ts");
const dir = mkdtempSync(join(tmpdir(), "check-api-"));
try {
  const out = join(dir, "schema.d.ts");
  execFileSync(
    join(root, "node_modules/.bin/openapi-typescript"),
    [spec, "-o", out],
    { stdio: "ignore", cwd: root },
  );
  if (readFileSync(out, "utf8") !== readFileSync(target, "utf8")) {
    console.error("openapi.json mudou: corre npm run gen:api");
    process.exit(1);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
