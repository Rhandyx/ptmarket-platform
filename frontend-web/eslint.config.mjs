import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

// O eslint-config-next já regista o plugin jsx-a11y; reutilizamos essa instância
// e ativamos o conjunto "recommended" completo (e não só as poucas regras do Next).
const a11yPlugin = nextVitals.map((c) => c.plugins?.["jsx-a11y"]).find(Boolean);
const a11yRules = a11yPlugin?.configs?.recommended?.rules ?? {};

export const guardRules = {
  "no-alert": "error",
  "no-restricted-properties": [
    "error",
    ...["alert", "confirm", "prompt"].flatMap((property) => [
      { object: "window", property, message: "Pop-ups nativos são proibidos." },
      { object: "globalThis", property, message: "Pop-ups nativos são proibidos." },
    ]),
  ],
  "react/no-danger": "error",
  ...a11yRules,
};

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  { rules: guardRules },
  globalIgnores([".next/**", "out/**", "build/**", "coverage/**", "next-env.d.ts"]),
]);
