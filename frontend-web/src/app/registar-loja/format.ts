// Formatação pt-PT a partir de inteiros. Sem contas com floats: só divisão inteira e resto.

function assertInt(n: number): void {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("Valor inteiro não negativo esperado.");
}

/** 800 → "8%", 650 → "6,5%", 625 → "6,25%", 5 → "0,05%". */
export function formatBps(bps: number): string {
  assertInt(bps);
  const whole = Math.trunc(bps / 100);
  const rest = bps % 100;
  if (rest === 0) return `${whole}%`;
  const dec = String(rest).padStart(2, "0").replace(/0$/, "");
  return `${whole},${dec}%`;
}

const eur0 = new Intl.NumberFormat("pt-PT", { style: "currency", currency: "EUR", maximumFractionDigits: 0 });
const eur2 = new Intl.NumberFormat("pt-PT", { style: "currency", currency: "EUR", minimumFractionDigits: 2 });

/** Cêntimos → euros. O Intl recebe o decimal exato como texto ("12.50"), nunca um float. */
export function formatCents(cents: number): string {
  assertInt(cents);
  const whole = Math.trunc(cents / 100);
  const rest = cents % 100;
  if (rest === 0) return eur0.format(`${whole}` as unknown as number);
  return eur2.format(`${whole}.${String(rest).padStart(2, "0")}` as unknown as number);
}
