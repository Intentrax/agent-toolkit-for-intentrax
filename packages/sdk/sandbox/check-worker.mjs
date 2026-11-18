// Worker side of check-runner.mjs: imports the developer's check module and
// either describes its exports or calls its check once with the probe. The
// parent terminates this worker as soon as it posts, so nothing the check
// leaves behind outlives the answer.

import { parentPort, workerData } from "node:worker_threads";

const { href, mode, probe } = workerData;

try {
  const mod = await import(href);
  const check = typeof mod.default === "function" ? mod.default : typeof mod.check === "function" ? mod.check : null;
  if (mode === "describe") {
    parentPort.postMessage({
      ok: true,
      value: {
        has_check: check !== null,
        expected: mod.expected === undefined ? null : mod.expected,
        resource: mod.resource === undefined ? null : mod.resource,
      },
    });
  } else if (check === null) {
    parentPort.postMessage({ ok: false, error: "module exports no check function" });
  } else {
    const value = await check(probe);
    parentPort.postMessage({ ok: true, value: value === undefined ? null : value });
  }
} catch (err) {
  parentPort.postMessage({ ok: false, error: String(err && err.message ? err.message : err).slice(0, 200) });
}
