import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "hench-publisher-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const site = join(root, "site"), bin = join(root, "bin"), network = join(root, "network-attempt");
  mkdirSync(site); mkdirSync(bin);
  writeFileSync(join(site, "index.html"), "public fixture");
  // Any external operation is recorded and stopped; malformed input must not reach it.
  writeFileSync(join(bin, "nak"), '#!/bin/sh\n: > "$PUBLISH_NETWORK_LOG"\nexit 1\n', { mode: 0o700 });
  const run = (relay = "ws://localhost:10547") => spawnSync("bash", [fileURLToPath(new URL("publish.sh", import.meta.url)), site], {
    encoding: "utf8", timeout: 5000,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, PUBLISH_NETWORK_LOG: network,
      NSITE_SEC: "01".repeat(32), NSITE_RELAY: relay, NSITE_BLOSSOM_HOST: "localhost:10547" },
  });
  return { site, network, run };
}

test("public lookalike hosts cannot use the built-in publisher key", (t) => {
  const { network, run } = fixture(t);
  for (const relay of ["ws://localhost.attacker.invalid", "ws://127.attacker.invalid"]) {
    const result = run(relay);
    assert.equal(result.error, undefined);
    assert.notEqual(result.status, 0);
    assert.equal(existsSync(network), false, "must refuse before uploading or publishing");
  }
});

test("newline filenames are rejected before any file is uploaded", (t) => {
  const { site, network, run } = fixture(t);
  writeFileSync(join(site, "index.html\n-private"), "unpublishable fixture");
  writeFileSync(`${site}-private`, "private sibling fixture");
  const result = run();
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.equal(existsSync(network), false, "malformed paths must not begin publication");
});
