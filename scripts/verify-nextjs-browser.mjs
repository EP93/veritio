#!/usr/bin/env node
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { chromium } from "playwright";

const root = new URL("..", import.meta.url);
const exampleDir = new URL("../examples/nextjs-better-auth", import.meta.url);
const port = Number(process.env.VERITIO_NEXT_BROWSER_PORT ?? "3020");
const baseUrl = `http://127.0.0.1:${port}`;
const existingBaseUrl = process.env.VERITIO_NEXT_BROWSER_BASE_URL ?? "http://localhost:3000";
const browserChannel = process.env.VERITIO_BROWSER_CHANNEL || undefined;
const viewports = [
  { name: "desktop", width: 1440, height: 1200 },
  { name: "mobile", width: 390, height: 844 },
];

/**
 * Runs the Next.js governed-change reference UI in a disposable dev server so
 * browser assertions exercise the same server-action boundary users click.
 */
async function main() {
  if (await isVeritioNextApp(existingBaseUrl)) {
    await verifyBrowserFlow(existingBaseUrl);
    console.log(`Next.js governed-change browser smoke passed against ${existingBaseUrl}.`);
    return;
  }

  const server = spawn(
    "bun",
    ["run", "--cwd", filePath(exampleDir), "dev", "--", "-H", "127.0.0.1", "-p", String(port)],
    {
      cwd: filePath(root),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const output = [];
  server.stdout.on("data", (chunk) => output.push(chunk.toString()));
  server.stderr.on("data", (chunk) => output.push(chunk.toString()));

  try {
    await waitForHttp(baseUrl, 45_000);
    await verifyBrowserFlow(baseUrl);
    console.log("Next.js governed-change browser smoke passed.");
  } finally {
    server.kill("SIGTERM");
    await Promise.race([onceExit(server), delay(5_000).then(() => server.kill("SIGKILL"))]);
    if (process.env.VERITIO_BROWSER_DEBUG === "1") {
      console.log(output.join(""));
    }
  }
}

/**
 * Reuses an already-running local Next example when present, which avoids Next's
 * single-dev-server lock while still verifying the browser-visible product path.
 */
async function isVeritioNextApp(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      return false;
    }
    const text = await response.text();
    return text.includes("Veritio") || text.includes("Server-owned governed CRUD reference");
  } catch {
    return false;
  }
}

/**
 * Runs the reference agent session and verifies the browser-visible governed
 * recalculations without exposing server-only HMAC material.
 */
async function verifyBrowserFlow(url) {
  const browser = await chromium.launch({ headless: true, channel: browserChannel });
  try {
    for (const viewport of viewports) {
      const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height } });
      const consoleErrors = [];
      page.on("console", (message) => {
        if (message.type() === "error") {
          consoleErrors.push(message.text());
        }
      });
      page.on("pageerror", (error) => consoleErrors.push(error.message));
      try {
        await page.goto(url, { waitUntil: "domcontentloaded" });
        await page.getByRole("button", { name: "Run agent session", exact: true }).click();
        await page.getByText("Recalculated 2", { exact: true }).waitFor({ timeout: 15_000 });
        const text = await page.locator("body").innerText();
        assertIncludes(text, "Agent sessions", viewport.name);
        assertIncludes(text, "Recalculated 2", viewport.name);
        assertIncludes(text, "veritio-cost-agent (cost_agent_7)", viewport.name);
        assertIncludes(text, "anthropic/claude-opus-4-8", viewport.name);
        assertIncludes(text, "Approved", viewport.name);
        assertIncludes(text, "Captured locally", viewport.name);
        assertIncludes(text, "Recent governed changes", viewport.name);
        assertIncludes(text, "project_entry.estimate.recalculation", viewport.name);
        assertIncludes(text, "Tower A — structural estimate", viewport.name);
        assertIncludes(text, "Tower B — facade package", viewport.name);
        assertExcludes(text, "nextjs-example-keyed-digest-secret", viewport.name);
        if (consoleErrors.length > 0) {
          throw new Error(`${viewport.name} browser console errors: ${consoleErrors.join("\n")}`);
        }
      } finally {
        await page.close();
      }
    }
  } finally {
    await browser.close();
  }
}

/**
 * Waits for the dev server before launching the browser, surfacing startup
 * failures as a bounded timeout rather than a hanging verification command.
 */
async function waitForHttp(url, timeoutMs) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // The server is still starting.
    }
    await delay(500);
  }
  throw new Error(`timed out waiting for ${url}`);
}

/**
 * Resolves URL objects to local filesystem paths without depending on cwd.
 */
function filePath(url) {
  return decodeURIComponent(url.pathname);
}

/**
 * Converts child-process completion into a promise for cleanup in all outcomes.
 */
function onceExit(child) {
  return new Promise((resolve) => child.once("exit", resolve));
}

/**
 * Fails with the missing UI text so browser smoke regressions are actionable.
 */
function assertIncludes(text, expected, viewportName) {
  if (!text.includes(expected)) {
    throw new Error(`expected ${viewportName} browser text to include ${expected}`);
  }
}

/**
 * Fails when prohibited raw payload or key material appears in browser text.
 */
function assertExcludes(text, prohibited, viewportName) {
  if (text.includes(prohibited)) {
    throw new Error(`${viewportName} browser text exposed prohibited value ${prohibited}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
