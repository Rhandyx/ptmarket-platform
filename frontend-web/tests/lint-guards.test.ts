import { ESLint } from "eslint";
import stylelint from "stylelint";
import { describe, expect, it } from "vitest";

async function eslintRules(code: string): Promise<string[]> {
  const eslint = new ESLint({ cwd: process.cwd() });
  const [res] = await eslint.lintText(code, { filePath: "src/app/fixture.tsx" });
  return (res?.messages ?? []).map((m) => m.ruleId ?? "");
}

async function css(code: string, codeFilename: string): Promise<string[]> {
  const out = await stylelint.lint({ code, codeFilename, cwd: process.cwd() });
  return (out.results[0]?.warnings ?? []).map((w) => w.rule);
}

describe("ESLint recusa pop-ups nativos e HTML perigoso", () => {
  it.each([
    ["alert('x')", "no-alert"],
    ["window.confirm('x')", "no-restricted-properties"],
    ["prompt()", "no-alert"],
    ["window.alert('x')", "no-restricted-properties"],
  ])("%s", async (stmt, rule) => {
    const rules = await eslintRules(`export function f() { ${stmt}; }\n`);
    expect(rules).toContain(rule);
  });

  it("dangerouslySetInnerHTML", async () => {
    const rules = await eslintRules(
      `export default function C({ h }: { h: string }) { return <div dangerouslySetInnerHTML={{ __html: h }} />; }\n`,
    );
    expect(rules).toContain("react/no-danger");
  });

  it("jsx-a11y ativo (div clicável)", async () => {
    const rules = await eslintRules(`export default function C() { return <div onClick={() => {}}>x</div>; }\n`);
    expect(rules.some((r) => r.startsWith("jsx-a11y/"))).toBe(true);
  });
});

describe("Stylelint recusa px de layout e cores fora dos tokens", () => {
  it("margin: 12px", async () => {
    expect(await css("a { margin: 12px; }\n", "src/x.css")).toContain("declaration-property-value-disallowed-list");
  });
  it("color: #fff fora de tokens.css", async () => {
    expect(await css("a { color: #fff; }\n", "src/x.css")).toContain("color-no-hex");
  });
  it("cor literal permitida em tokens.css", async () => {
    expect(await css(":root { --color-x: #ffffff; }\n", "src/styles/tokens.css")).not.toContain("color-no-hex");
  });
  it("px permitido em border/outline", async () => {
    expect(await css("a { border: 1px solid var(--color-border); }\n", "src/x.css")).toEqual([]);
  });
});
