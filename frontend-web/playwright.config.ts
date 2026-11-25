import { defineConfig, devices } from "@playwright/test";

const PORT = 3100;
const sizes = [
  { name: "375", viewport: { width: 375, height: 812 } },
  { name: "1440", viewport: { width: 1440, height: 900 } },
] as const;
const themes = [
  { name: "claro", colorScheme: "light" as const },
  { name: "escuro", colorScheme: "dark" as const },
];

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./e2e/.results",
  fullyParallel: true,
  reporter: [["list"]],
  use: { baseURL: `http://localhost:${PORT}`, ...devices["Desktop Chrome"] },
  projects: sizes.flatMap((s) =>
    themes.map((t) => ({
      name: `${s.name}-${t.name}`,
      use: { ...devices["Desktop Chrome"], viewport: s.viewport, colorScheme: t.colorScheme },
    })),
  ),
  webServer: {
    command: `npm run build && npx next start -p ${PORT}`,
    url: `http://localhost:${PORT}/design-system`,
    reuseExistingServer: false,
    timeout: 240_000,
  },
});
