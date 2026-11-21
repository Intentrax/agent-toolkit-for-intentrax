// Worker side of confirm.mjs's read-back workers. Two kinds:
//   - "recipe": rebuilds a read-back recipe from plain-data options and calls
//     its check once (a recipe is a factory, not a module's default export);
//   - "module": imports a { module } check and calls its default export (or
//     `check`) with the probe, as the sandbox's check-worker.mjs does.
// The parent terminates this worker as soon as it posts (or on timeout), so
// sockets or timers the read leaves open cannot outlive the answer.
//
// Errors are posted WHOLE. The parent redacts them with every secret it knows
// (the recipe's and the caller's) and only then cuts them to display length.
// Cutting here first could split a secret and leave a prefix that exact-match
// redaction can no longer find. (This is why { module } checks do not use the
// sandbox's check-worker.mjs, which cuts errors at 200 characters.)

import { parentPort, workerData } from "node:worker_threads";

const { kind = "recipe", href, exportName, options, probe } = workerData;

try {
  const mod = await import(href);
  let value;
  if (kind === "module") {
    const check = typeof mod.default === "function" ? mod.default : typeof mod.check === "function" ? mod.check : null;
    if (check === null) throw new Error("module exports no check function");
    value = await check(probe);
  } else {
    if (typeof mod[exportName] !== "function") throw new Error("recipe module has no export " + exportName);
    value = await mod[exportName](options)({});
  }
  parentPort.postMessage({ ok: true, value: value === undefined ? null : value });
} catch (err) {
  parentPort.postMessage({ ok: false, error: String(err && err.message ? err.message : err) });
}
