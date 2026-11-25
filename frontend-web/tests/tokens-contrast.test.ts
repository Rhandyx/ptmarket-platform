import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const css = readFileSync("src/styles/tokens.css", "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

type Pair = { light: string; dark: string };

/** Lê os blocos `seletor { --color-x: light-dark(a, b); }`, por seletor. */
function parse(): Map<string, Map<string, Pair>> {
  const blocks = new Map<string, Map<string, Pair>>();
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const sel = (m[1] ?? "").trim();
    const vars = new Map<string, Pair>();
    for (const d of (m[2] ?? "").matchAll(/(--color-[\w-]+):\s*light-dark\(\s*(#[0-9a-f]{3,6})\s*,\s*(#[0-9a-f]{3,6})\s*\)/gi)) {
      vars.set(d[1] as string, { light: d[2] as string, dark: d[3] as string });
    }
    if (vars.size) blocks.set(sel, vars);
  }
  return blocks;
}

function channel(hex: string): [number, number, number] {
  let h = hex.slice(1);
  if (h.length === 3) h = [...h].map((c) => c + c).join("");
  const n = parseInt(h, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function luminance(hex: string): number {
  const [r, g, b] = channel(hex).map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function ratio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const blocks = parse();
const scopes = [":root", '[data-template="bairro"]', '[data-template="editorial"]', '[data-template="catalogo"]'];

const textPairs: [string, string][] = [
  ["--color-text", "--color-bg"],
  ["--color-text", "--color-surface"],
  ["--color-text-muted", "--color-bg"],
  ["--color-text-muted", "--color-surface"],
  ["--color-primary", "--color-bg"],
  ["--color-primary", "--color-surface"],
  ["--color-on-primary", "--color-primary"],
  ["--color-on-secondary", "--color-secondary"],
];

describe("contraste dos tokens (WCAG AA)", () => {
  it("os 4 âmbitos existem", () => {
    for (const s of scopes) expect(blocks.has(s), s).toBe(true);
  });

  for (const scope of scopes) {
    for (const mode of ["light", "dark"] as const) {
      const vars = (name: string): string => {
        const v = blocks.get(scope)?.get(name) ?? blocks.get(":root")?.get(name);
        if (!v) throw new Error(`token em falta: ${name}`);
        return v[mode];
      };
      it(`${scope} · ${mode}: texto ≥ 4,5:1`, () => {
        for (const [fg, bg] of textPairs) {
          expect(ratio(vars(fg), vars(bg)), `${fg} sobre ${bg}`).toBeGreaterThanOrEqual(4.5);
        }
      });
      it(`${scope} · ${mode}: foco ≥ 3:1 sobre fundo e superfície`, () => {
        expect(ratio(vars("--color-focus"), vars("--color-bg"))).toBeGreaterThanOrEqual(3);
        expect(ratio(vars("--color-focus"), vars("--color-surface"))).toBeGreaterThanOrEqual(3);
      });
    }
  }
});
