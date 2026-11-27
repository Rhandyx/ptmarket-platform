import { createHmac } from "node:crypto";
import AxeBuilder from "@axe-core/playwright";
import { expect, test as base, type Page } from "@playwright/test";

// Painel de backoffice (cartão 04/07).
// - Sempre: /painel num Host que não é o da plataforma → 404.
// - PLATFORM_ADMIN_HOST=localhost (herdado pelo `next start` do webServer): página de entrada,
//   axe, teclado, erros com e sem JavaScript (não precisam da API).
// - E2E_BACKEND=1: redirecionamentos que dependem da API.
// - E2E_STAFF_EMAIL + E2E_STAFF_PASSWORD + E2E_STAFF_TOTP_SECRET (utilizador de dev): fluxo completo
//   login → 2FA → painel → terminar sessão, com e sem JavaScript, só com teclado.

const ADMIN = process.env.PLATFORM_ADMIN_HOST === "localhost";
const BACKEND = process.env.E2E_BACKEND === "1";
const STAFF = {
  email: process.env.E2E_STAFF_EMAIL ?? "",
  password: process.env.E2E_STAFF_PASSWORD ?? "",
  totp: process.env.E2E_STAFF_TOTP_SECRET ?? "",
};
const HAS_STAFF = BACKEND && !!STAFF.email && !!STAFF.password && !!STAFF.totp;

const SHOTS = "e2e/__screenshots__";

/** Qualquer diálogo nativo (alert/confirm/prompt) faz o teste falhar. */
const test = base.extend<{ nativeDialogs: string[] }>({
  nativeDialogs: [
    async ({ page }, use) => {
      const seen: string[] = [];
      page.on("dialog", (d) => {
        seen.push(`${d.type()}: ${d.message()}`);
        void d.dismiss();
      });
      await use(seen);
      expect(seen, "o browser emitiu um diálogo nativo").toEqual([]);
    },
    { auto: true },
  ],
});

async function axeClean(page: Page) {
  const res = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" | ")}`)).toEqual([]);
}

/** TOTP RFC 6238 (SHA-1, 6 dígitos, 30 s) para o utilizador de dev. */
function totp(secretB32: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secretB32.replace(/[\s=-]/g, "").toUpperCase()) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw new Error("segredo TOTP inválido");
    bits += v.toString(2).padStart(5, "0");
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1]! & 0xf;
  const n = (h.readUInt32BE(o) & 0x7fffffff) % 1_000_000;
  return n.toString().padStart(6, "0");
}

test("/painel num Host que não é o da plataforma → 404", async ({ request, baseURL }) => {
  // Com PLATFORM_ADMIN_HOST=localhost, 127.0.0.1 é "outro Host"; sem a variável, qualquer Host é.
  const origin = ADMIN ? baseURL!.replace("localhost", "127.0.0.1") : baseURL!;
  for (const path of ["/painel", "/painel/entrar", "/painel/2fa"]) {
    const res = await request.get(`${origin}${path}`, { maxRedirects: 0 });
    expect(res.status(), path).toBe(404);
  }
});

test.describe("entrar (Host da plataforma)", () => {
  test.skip(!ADMIN, "precisa de PLATFORM_ADMIN_HOST=localhost");

  test("página: noindex, sem cache, campos corretos, axe", async ({ page }, info) => {
    const res = await page.goto("/painel/entrar");
    expect(res?.status()).toBe(200);
    expect(res?.headers()["cache-control"] ?? "").toMatch(/no-store/);
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
    await expect(page.getByRole("heading", { level: 1, name: "Entrar no painel" })).toBeVisible();
    const email = page.getByLabel("Email");
    const password = page.getByLabel("Palavra-passe");
    await expect(email).toHaveAttribute("autocomplete", "username");
    await expect(password).toHaveAttribute("autocomplete", "current-password");
    await expect(password).not.toHaveAttribute("maxlength", /.*/);
    expect(await page.locator("dialog[open]").count()).toBe(0);
    await axeClean(page);
    await page.screenshot({ path: `${SHOTS}/${info.project.name}-painel-entrar.png`, fullPage: true });
  });

  test("com JavaScript, só teclado: erros por campo, foco no primeiro erro, axe", async ({ page }, info) => {
    await page.goto("/painel/entrar");
    await page.getByLabel("Email").focus();
    await page.keyboard.press("Tab");
    await expect(page.getByLabel("Palavra-passe")).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: "Entrar" })).toBeFocused();
    await page.keyboard.press("Enter");
    const email = page.getByLabel("Email");
    await expect(page.getByText("Indique o email.")).toBeVisible();
    await expect(email).toBeFocused();
    await expect(email).toHaveAttribute("aria-invalid", "true");
    await expect(email).toHaveAttribute("aria-describedby", /entrar-email-erro/);
    await axeClean(page);
    await page.screenshot({ path: `${SHOTS}/${info.project.name}-painel-entrar-erro.png`, fullPage: true });
  });

  test("sem JavaScript: o formulário submete e mostra os erros", async ({ browser, baseURL }) => {
    const ctx = await browser.newContext({ javaScriptEnabled: false, baseURL });
    const page = await ctx.newPage();
    await page.goto("/painel/entrar");
    await page.getByLabel("Email").focus();
    await page.keyboard.press("Enter");
    await expect(page.getByText("Indique o email.")).toBeVisible();
    await expect(page.getByText("Indique a palavra-passe.")).toBeVisible();

    // Credenciais erradas: mensagem única (ou indisponível, se a API não estiver a correr).
    await page.getByLabel("Email").fill("ninguem@exemplo.pt");
    await page.getByLabel("Palavra-passe").fill("palavra-passe-errada");
    await page.getByLabel("Palavra-passe").press("Enter");
    // Filtrar pelo texto: com JS, o anunciador de rotas do Next também tem role="alert".
    await expect(
      page
        .getByRole("alert")
        .filter({ hasText: /Email ou palavra-passe incorretos\.|Serviço indisponível\. Tente de novo\.|Demasiadas tentativas/ }),
    ).toBeVisible();
    await expect(page.getByLabel("Email")).toHaveValue("ninguem@exemplo.pt");
    await expect(page.getByLabel("Palavra-passe")).toHaveValue("");
    expect(page.url()).toMatch(/\/painel\/entrar$/);
    await ctx.close();
  });

  test("sem sessão: /painel e /painel/2fa → /painel/entrar", async ({ page }) => {
    test.skip(!BACKEND, "precisa da API (E2E_BACKEND=1)");
    for (const path of ["/painel", "/painel/2fa"]) {
      await page.goto(path);
      await expect(page).toHaveURL(/\/painel\/entrar$/);
    }
  });
});

test.describe("fluxo completo com o utilizador de dev", () => {
  test.describe.configure({ mode: "serial" });
  test.skip(!ADMIN || !HAS_STAFF, "precisa de PLATFORM_ADMIN_HOST=localhost, E2E_BACKEND=1 e E2E_STAFF_*");

  /** Espera pela janela TOTP seguinte (o mesmo código não pode ser usado duas vezes). */
  async function freshCode(page: Page): Promise<string> {
    const left = 30_000 - (Date.now() % 30_000);
    await page.waitForTimeout(left + 500);
    return totp(STAFF.totp);
  }

  for (const js of [true, false]) {
    test(`login → 2FA → painel → terminar sessão (${js ? "com" : "sem"} JavaScript, só teclado)`, async ({ browser, baseURL }, info) => {
      test.skip(info.project.name !== "1440-claro", "um só projeto: o utilizador e o TOTP são partilhados");
      test.setTimeout(120_000);
      const ctx = await browser.newContext({ javaScriptEnabled: js, baseURL });
      const page = await ctx.newPage();
      const dialogs: string[] = [];
      page.on("dialog", (d) => {
        dialogs.push(d.type());
        void d.dismiss();
      });

      await page.goto("/painel/entrar");
      await page.getByLabel("Email").focus();
      await page.keyboard.type(STAFF.email);
      await page.keyboard.press("Tab");
      await page.keyboard.type(STAFF.password);
      await page.keyboard.press("Enter");

      await expect(page).toHaveURL(/\/painel\/2fa$/);
      await expect(page.getByRole("heading", { level: 1, name: "Verificação em dois passos" })).toBeVisible();
      if (js) await axeClean(page);
      const code = page.getByRole("textbox", { name: "Código de 6 dígitos", exact: true });
      await expect(code).toHaveAttribute("autocomplete", "one-time-code");
      await expect(code).toHaveAttribute("inputmode", "numeric");
      // Código errado: mensagem única no role="alert" (filtrado pelo texto: o anunciador de rotas
      // do Next também é role="alert") e foco de volta no campo.
      await code.focus();
      await page.keyboard.type("000000");
      await page.keyboard.press("Enter");
      await expect(page.getByRole("alert").filter({ hasText: "Código incorreto ou já usado." })).toBeVisible();
      const again = page.getByRole("textbox", { name: "Código de 6 dígitos", exact: true });
      await expect(again).toHaveAttribute("aria-invalid", "true");
      if (js) await expect(again).toBeFocused();
      const value = await freshCode(page);
      await again.fill("");
      await again.focus();
      await page.keyboard.type(value);
      await page.keyboard.press("Enter");

      await expect(page).toHaveURL(/\/painel$/);
      await expect(page.getByRole("heading", { level: 1, name: /^Olá, / })).toBeVisible();
      if (js) await axeClean(page);
      const cookies = await ctx.cookies();
      const admin = cookies.find((c) => c.name === "__Host-ptm_admin");
      expect(admin?.httpOnly).toBe(true);
      expect(admin?.sameSite).toBe("Strict");

      await page.getByRole("button", { name: "Terminar sessão" }).focus();
      await page.keyboard.press("Enter");
      await expect(page).toHaveURL(/\/painel\/entrar$/);
      await page.goto("/painel");
      await expect(page).toHaveURL(/\/painel\/entrar$/);
      expect(dialogs, "o browser emitiu um diálogo nativo").toEqual([]);
      await ctx.close();
    });
  }
});
