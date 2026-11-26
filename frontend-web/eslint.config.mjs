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

// Proíbe importar lib/api/server em ficheiros "use client".
const localPlugin = {
  rules: {
    "no-server-api-in-client": {
      create(context) {
        return {
          Program(node) {
            const isClient = node.body.some(
              (n) => n.type === "ExpressionStatement" && n.directive === "use client",
            );
            if (!isClient) return;
            for (const n of node.body) {
              if (n.type === "ImportDeclaration" && /(^|\/)lib\/api\/server$|^\.\/server$/.test(n.source.value)) {
                context.report({ node: n, message: "server.ts é só de servidor; não importar em código de cliente." });
              }
            }
          },
        };
      },
    },
  },
};

const apiGuards = {
  "no-restricted-syntax": [
    "error",
    {
      selector: "CallExpression[callee.name='fetch'][arguments.0.value=/^\\/api\\//]",
      message: "Chamadas a /api/ só via src/lib/api (cliente gerado).",
    },
    {
      selector: "CallExpression[callee.name='fetch'] > TemplateLiteral.arguments:first-child[quasis.0.value.raw=/^\\/api\\//]",
      message: "Chamadas a /api/ só via src/lib/api (cliente gerado).",
    },
    {
      selector: "Literal[value=/^NEXT_PUBLIC_.*(TOKEN|SECRET)/]",
      message: "Segredos nunca em NEXT_PUBLIC_*.",
    },
  ],
};

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  { rules: guardRules },
  { ignores: ["src/lib/api/**"], rules: apiGuards },
  {
    files: ["**/*.{ts,tsx,js,jsx}"],
    plugins: { local: localPlugin },
    rules: { "local/no-server-api-in-client": "error" },
  },
  globalIgnores(["src/lib/api/schema.d.ts", ".next/**", "out/**", "build/**", "coverage/**", "next-env.d.ts"]),
]);
