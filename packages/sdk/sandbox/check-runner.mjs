// Runs a developer's `--check` module in a worker thread.
//
// The sandbox never executes user check code on its own thread: both reading
// the module's exports ("describe") and calling the check ("read") happen in
// a worker that is terminated as soon as it answers, fails, or the caller's
// AbortSignal fires (the read timeout). Sockets, timers or a promise that
// never settles inside a check therefore cannot keep the CLI alive.
//
// The worker side is check-worker.mjs. Values cross the boundary by
// structured clone, so a check can only return data (functions and other
// non-cloneable values are an error).

import { Worker } from "node:worker_threads";

// Worker exit codes that mean "never answered" rather than "failed":
// 13 = unsettled top-level await (the worker awaits the check at top level),
// 0 = clean exit without posting.
const NO_ANSWER_EXIT_CODES = new Set([0, 13]);

export function runCheckWorker({ href, mode, probe = null, signal = null }) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(signal.reason);
      return;
    }
    const worker = new Worker(new URL("./check-worker.mjs", import.meta.url), {
      workerData: { href, mode, probe },
    });
    let settled = false;
    const onAbort = () => finish(() => reject(signal.reason));
    function finish(settle) {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener("abort", onAbort);
      // Terminate unconditionally: the check may have left handles open.
      worker.terminate().catch(() => {});
      settle();
    }
    worker.once("message", (m) => finish(() => (m && m.ok ? resolve(m.value) : reject(new Error(m && m.error ? m.error : "check failed")))));
    worker.once("error", (err) => finish(() => reject(err)));
    worker.once("exit", (code) => {
      // A check whose promise never settles and holds nothing open lets the
      // worker exit without answering (code 13: unsettled top-level await).
      // That is "no result", not an error: keep waiting so the caller's
      // timeout reports it, the same on a fast or slow host. Without a signal
      // there is no timeout to wait for.
      if (NO_ANSWER_EXIT_CODES.has(code) && signal) return;
      finish(() => reject(new Error("check worker exited with code " + code)));
    });
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
  });
}

// Read a check module's exports without running its code on this thread.
export async function describeCheck(href, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("loading the check module took longer than " + timeoutMs + " ms")), timeoutMs);
  try {
    return await runCheckWorker({ href, mode: "describe", signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
