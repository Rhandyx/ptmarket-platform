import AxeBuilder from "@axe-core/playwright";
import { expect, test as base, type Locator, type Page } from "@playwright/test";

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

const SHOTS = "e2e/__screenshots__";

async function axeClean(page: Page) {
  const res = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" | ")}`)).toEqual([]);
}

async function settled(el: Locator) {
  await expect(el).toHaveCSS("opacity", "1");
  await expect(el).toBeVisible();
}

async function shot(page: Page, name: string, project: string) {
  await page.screenshot({ path: `${SHOTS}/${project}-${name}.png` });
}

async function focusInside(page: Page, dialog: Locator) {
  // Nativo: ao sair do último controlo o foco passa para a UI do browser (activeElement = body),
  // nunca para o conteúdo da página, que está inerte.
  return dialog.evaluate((d) => d.contains(document.activeElement) || document.activeElement === document.body);
}

test.beforeEach(async ({ page }) => {
  await page.goto("/design-system");
  await expect(page.getByRole("heading", { level: 1, name: "Sobreposições" })).toBeVisible();
});

test("nada abre ao carregar e a página não tem violações axe", async ({ page }) => {
  expect(await page.locator("dialog[open]").count()).toBe(0);
  expect(await page.locator(":popover-open").count()).toBe(0);
  await expect(page.getByRole("status", { name: "Notificações" }).locator("> *")).toHaveCount(0);
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
  await axeClean(page);
});

test("Modal: teclado, foco preso, Esc, foco devolvido, axe", async ({ page }, info) => {
  const trigger = page.getByRole("button", { name: "Abrir modal" });
  await trigger.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: "Bem-vindo à sua loja" });
  await settled(dialog);
  await axeClean(page);
  await shot(page, "modal", info.project.name);
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press("Tab");
    expect(await focusInside(page, dialog)).toBe(true);
  }
  await page.keyboard.press("Shift+Tab");
  expect(await focusInside(page, dialog)).toBe(true);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("Modal: ponteiro (Fechar e backdrop dismissible)", async ({ page }) => {
  const trigger = page.getByRole("button", { name: "Abrir modal" });
  const dialog = page.getByRole("dialog", { name: "Bem-vindo à sua loja" });
  await trigger.click();
  await settled(dialog);
  await dialog.getByRole("button", { name: "Fechar" }).click();
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();

  await trigger.click();
  await settled(dialog);
  await page.mouse.click(2, 2);
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("ConfirmDialog: foco inicial em Cancelar, não dismissible, confirma com toast", async ({ page }, info) => {
  const trigger = page.getByRole("button", { name: "Apagar produto" });
  const dialog = page.getByRole("dialog", { name: "Apagar este produto?" });
  await trigger.click();
  await settled(dialog);
  await expect(dialog.getByRole("button", { name: "Cancelar" })).toBeFocused();
  await axeClean(page);
  await shot(page, "confirmacao", info.project.name);
  await page.mouse.click(2, 2);
  await expect(dialog).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();

  await trigger.click();
  await settled(dialog);
  await dialog.getByRole("button", { name: "Apagar" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("status", { name: "Notificações" })).toContainText("Produto apagado");
});

test("Drawer: ancoragem, foco preso, Esc, axe", async ({ page }, info) => {
  const trigger = page.getByRole("button", { name: "Abrir drawer" });
  const dialog = page.getByRole("dialog", { name: "Filtros" });
  await trigger.focus();
  await page.keyboard.press("Space");
  await settled(dialog);
  await expect.poll(async () => (await dialog.boundingBox())?.x).toBeDefined();
  await page.waitForTimeout(400);
  const box = (await dialog.boundingBox())!;
  const vp = page.viewportSize()!;
  if (vp.width > 640) {
    expect(Math.round(box.x + box.width)).toBe(vp.width);
    expect(box.width).toBeLessThanOrEqual(448 + 1);
  } else {
    expect(Math.round(box.y + box.height)).toBe(vp.height);
    expect(Math.round(box.width)).toBe(vp.width);
  }
  await axeClean(page);
  await shot(page, "drawer", info.project.name);
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press("Tab");
    expect(await focusInside(page, dialog)).toBe(true);
  }
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("Popover: ponteiro, Esc, clique fora, foco devolvido, axe", async ({ page }, info) => {
  const trigger = page.getByRole("button", { name: "Mais informação" });
  const panel = page.getByRole("dialog", { name: "Preço com IVA" });
  await trigger.click();
  await settled(panel);
  await axeClean(page);
  await shot(page, "popover", info.project.name);
  const t = (await trigger.boundingBox())!;
  const p = (await panel.boundingBox())!;
  expect(Math.abs(p.y - (t.y + t.height)) < 200 || Math.abs(p.y + p.height - t.y) < 200).toBe(true);
  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
  await expect(trigger).toBeFocused();

  await trigger.focus();
  await page.keyboard.press("Enter");
  await settled(panel);
  await page.mouse.click(2, 2);
  await expect(panel).toBeHidden();
});

test("Popover abre com JavaScript desativado", async ({ browser, baseURL }) => {
  const ctx = await browser.newContext({ javaScriptEnabled: false, baseURL });
  const page = await ctx.newPage();
  await page.goto("/design-system");
  const panel = page.getByRole("dialog", { name: "Preço com IVA" });
  await expect(panel).toBeHidden();
  await page.getByRole("button", { name: "Mais informação" }).click();
  await expect(panel).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
  await ctx.close();
});

test("Toast: não rouba foco, anuncia, pausa, erro persiste, máx. 3, axe", async ({ page }, info) => {
  await page.clock.install();
  await page.goto("/design-system");
  const polite = page.getByRole("status", { name: "Notificações" });
  const errors = page.getByRole("alert", { name: "Erros" });
  const ok = page.getByRole("button", { name: "Mostrar aviso" }).first();
  const bad = page.getByRole("button", { name: "Mostrar erro" });

  await ok.focus();
  await page.keyboard.press("Enter");
  await expect(polite).toContainText("Alterações guardadas");
  await expect(ok).toBeFocused();
  await bad.click();
  await expect(errors).toContainText("Não foi possível guardar");
  await expect(polite.locator("> *")).toHaveCount(1);
  await page.waitForTimeout(400);
  await axeClean(page);
  await shot(page, "toast", info.project.name);

  // Pausa ao pairar: passados 8 s continua lá.
  await polite.getByText("Alterações guardadas").hover();
  await page.clock.runFor(8000);
  await expect(polite).toContainText("Alterações guardadas");
  await page.mouse.move(0, 0);
  await page.clock.runFor(7000);
  await expect(polite.locator("> *")).toHaveCount(0);
  // O erro não desaparece sozinho.
  await expect(errors).toContainText("Não foi possível guardar");

  await errors.getByRole("button", { name: /Fechar notificação/ }).click();
  await expect(errors.locator("> *")).toHaveCount(0);

  for (let i = 0; i < 4; i++) await ok.click();
  await expect(polite.locator("> *")).toHaveCount(3);
});

test("prefers-reduced-motion: sem transição nem animação", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.getByRole("button", { name: "Abrir modal" }).click();
  const dialog = page.getByRole("dialog", { name: "Bem-vindo à sua loja" });
  await expect(dialog).toBeVisible();
  const dur = await dialog.evaluate((d) => getComputedStyle(d).transitionDuration);
  expect(dur.split(",").every((v) => parseFloat(v) === 0)).toBe(true);
  await dialog.getByRole("button", { name: "Mostrar aviso" }).click();
  const toast = page.getByRole("status", { name: "Notificações" }).locator("> *").first();
  await expect(toast).toBeVisible();
  expect(await toast.evaluate((e) => getComputedStyle(e).animationName)).toBe("none");
});
