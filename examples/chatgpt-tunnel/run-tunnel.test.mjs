import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { EXPECTED_DEMO_TOOLS, parseArguments, usage } from "./run-tunnel.mjs";

test("legacy tunnel launcher validates the current exact tunnel identifier", () => {
  assert.deepEqual(
    parseArguments([
      "--tunnel-id",
      "tunnel_0123456789abcdef0123456789abcdef",
      "--profile",
      "my-profile",
    ]),
    {
      help: false,
      profile: "my-profile",
      tunnelId: "tunnel_0123456789abcdef0123456789abcdef",
    },
  );
  assert.throws(
    () => parseArguments(["--tunnel-id", "tunnel_0123456789abcdef"]),
    /32 lowercase/u,
  );
  assert.deepEqual(EXPECTED_DEMO_TOOLS, [
    "docs.search",
    "gmail.send_email",
    "dangerous.delete_customer",
  ]);
});

test("legacy help clearly delegates to the First Run Concierge", () => {
  assert.match(usage(), /\.\/actionproxy chatgpt/u);
  assert.match(usage(), /hidden input/u);
  assert.doesNotMatch(usage(), /export CONTROL_PLANE_API_KEY/u);

  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./run-tunnel.mjs", import.meta.url)), "--help"],
    {
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /compatibility command delegates/u);
});
