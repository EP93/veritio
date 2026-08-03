import { describe, expect, test } from "bun:test";
import { buildCaptureEnv, buildCodexWrapper } from "../agent-config.js";
import { extractNotify, type LoginDeps, parseLoginArgs, runLogin, upsertNotify } from "../login.js";

describe("parseLoginArgs", () => {
  test("defaults to both agents against prod console", () => {
    const opts = parseLoginArgs(["login"]);
    expect(opts).toMatchObject({ agent: "both", consoleUrl: "https://console.getveritio.com", openBrowser: true });
  });

  test("accepts an agent selector and flags", () => {
    const opts = parseLoginArgs(["login", "codex", "--console-url", "http://localhost:3010", "--no-browser"]);
    expect(opts).toMatchObject({ agent: "codex", consoleUrl: "http://localhost:3010", openBrowser: false });
  });

  test("rejects unknown flags", () => {
    expect(() => parseLoginArgs(["login", "--wat"])).toThrow();
  });
});

describe("codex config surgery", () => {
  test("extractNotify reads an existing notify array", () => {
    expect(extractNotify('model = "x"\nnotify = ["/a/b", "turn-ended"]\n')).toEqual(["/a/b", "turn-ended"]);
    expect(extractNotify('model = "x"')).toBeNull();
  });

  test("upsertNotify replaces an existing line and appends when absent", () => {
    expect(upsertNotify('notify = ["old"]\nx = 1', 'notify = ["new"]')).toBe('notify = ["new"]\nx = 1');
    expect(upsertNotify("x = 1", 'notify = ["new"]')).toBe('x = 1\nnotify = ["new"]\n');
  });

  test("wrapper forwards an existing notifier before capture, never replacing it", () => {
    const wrapper = buildCodexWrapper("veritio-codex-notify", ["/existing/notifier", "turn-ended"]);
    expect(wrapper).toContain("'/existing/notifier' 'turn-ended' \"$@\" || true");
    expect(wrapper).toContain("nohup 'veritio-codex-notify' \"$@\" >/dev/null 2>&1 &");
  });
});

/** A scripted fetch + spy deps for the device flow. */
function harness(pollScript: unknown[]) {
  const files: Record<string, string> = {};
  const written: string[] = [];
  let pollIndex = 0;
  const deps: LoginDeps = {
    codexNotifyBin: "/workspace/adapters/codex/dist/notify.js",
    fetch: (async (url: string | URL | Request) => {
      const u = String(url);
      const body = u.endsWith("/api/device/code")
        ? {
            deviceCode: "dev_1",
            userCode: "ABCD-2345",
            verificationUri: "http://c/device",
            intervalSeconds: 0,
            expiresInSeconds: 60,
          }
        : pollScript[Math.min(pollIndex++, pollScript.length - 1)];
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
    write: (m) => written.push(m),
    async writeFile(path, contents) {
      files[path] = contents;
    },
    readCodexConfig: async () => 'model = "gpt-5"\nnotify = ["/existing/notifier", "turn-ended"]\n',
    async writeCodexConfig(contents) {
      files["__codex_config__"] = contents;
    },
    openBrowser: () => {},
    sleep: async () => {},
    now: () => 0,
  };
  return { deps, files, written };
}

describe("runLogin device flow", () => {
  test("approved: writes credentials + codex config, preserving existing notifier", async () => {
    const { deps, files } = harness([
      { status: "pending" },
      { status: "approved", token: "vrt_minted", projectId: "proj_x" },
    ]);
    const code = await runLogin(parseLoginArgs(["login", "codex"]), deps);
    expect(code).toBe(0);

    const creds = Object.entries(files).find(([p]) => p.endsWith("credentials.json"));
    expect(JSON.parse(creds![1])).toEqual({
      ingestUrl: "https://console.getveritio.com/api/ingest",
      ingestKey: "vrt_minted",
      tenantId: "proj_x",
    });
    const env = Object.entries(files).find(([p]) => p.endsWith("capture.env"));
    expect(env![1]).toBe(
      buildCaptureEnv({
        ingestUrl: "https://console.getveritio.com/api/ingest",
        ingestKey: "vrt_minted",
        tenantId: "proj_x",
      }),
    );
    expect(files["__codex_config__"]).toContain('notify = ["');
    const wrapper = Object.entries(files).find(([p]) => p.endsWith("notify-wrapper.sh"));
    expect(wrapper![1]).toContain("/existing/notifier");
    expect(wrapper![1]).toContain("'/workspace/adapters/codex/dist/notify.js'");
    expect(wrapper![1]).not.toContain("'veritio-codex-notify'");
  });

  test("expired: exits 1 and writes no credentials", async () => {
    const { deps, files } = harness([{ status: "expired" }]);
    const code = await runLogin(parseLoginArgs(["login", "codex"]), deps);
    expect(code).toBe(1);
    expect(Object.keys(files).some((p) => p.endsWith("credentials.json"))).toBe(false);
  });
});
