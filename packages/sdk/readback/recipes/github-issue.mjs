// Read-back recipe: GitHub issue or pull request state.
//
// Minimum scope: a fine-grained personal access token (or GitHub App token)
// limited to the one repository, with "Issues: Read-only" (for kind "issue")
// or "Pull requests: Read-only" (for kind "pull"); GitHub adds
// "Metadata: Read-only" automatically. Public repositories need no token
// (unauthenticated requests have a low rate limit).
//
//   const check = githubIssue({ owner: "acme", repo: "app", number: 42, token: process.env.GH_ISSUES_READ });
//   const check = githubIssue({ owner: "acme", repo: "app", number: 7, kind: "pull", octokit });
//
// kind "issue": GET /repos/{owner}/{repo}/issues/{number}
//   -> { number, state ("open" | "closed"), state_reason, is_pull_request }
// kind "pull":  GET /repos/{owner}/{repo}/pulls/{number}
//   -> { number, state ("open" | "closed"), merged, draft }
// (GitHub's issues endpoint also returns pull requests; `is_pull_request`
// says which.)

import { checkNotFoundAs, defineRecipe, getJson, pick, requireString, resolveFetch } from "./_shared.mjs";

const NAME = /^[A-Za-z0-9_.-]+$/;

/**
 * @param {object} opts
 * @param {string} opts.owner
 * @param {string} opts.repo
 * @param {number} opts.number
 * @param {"issue"|"pull"} [opts.kind]  default "issue"
 * @param {string} [opts.token]         fine-grained read-only token
 * @param {object} [opts.octokit]       an Octokit client (only rest.issues.get / rest.pulls.get are called)
 * @param {string} [opts.apiBase]       default https://api.github.com (GitHub Enterprise: https://HOST/api/v3)
 * @param {object} [opts.notFoundAs]
 * @param {Function} [opts.fetch]
 */
export function githubIssue(opts = {}) {
  const { owner, repo, number, kind = "issue", token, octokit, apiBase = "https://api.github.com", notFoundAs, fetch: fetchImpl } = opts;
  requireString("owner", owner, { pattern: NAME, max: 100 });
  requireString("repo", repo, { pattern: NAME, max: 100 });
  if (!Number.isSafeInteger(number) || number < 1) throw new TypeError("number must be a positive integer");
  if (kind !== "issue" && kind !== "pull") throw new TypeError('kind must be "issue" or "pull"');
  if (token !== undefined && octokit !== undefined) throw new TypeError("pass token or octokit, not both");
  if (token !== undefined) requireString("token", token, { max: 1000 });
  checkNotFoundAs(notFoundAs);

  const shape = (data) => {
    if (kind === "pull") return pick(data, ["number", "state", "merged", "draft"]);
    const out = pick(data, ["number", "state", "state_reason"]);
    if (data && typeof data === "object") out.is_pull_request = Object.prototype.hasOwnProperty.call(data, "pull_request");
    return out;
  };

  let read;
  if (octokit !== undefined) {
    const api = octokit && octokit.rest ? octokit.rest : octokit;
    const fn = kind === "pull" ? api && api.pulls && api.pulls.get : api && api.issues && api.issues.get;
    if (typeof fn !== "function") throw new TypeError("octokit must expose rest." + (kind === "pull" ? "pulls" : "issues") + ".get");
    read = async ({ signal }) => {
      const params = kind === "pull" ? { owner, repo, pull_number: number } : { owner, repo, issue_number: number };
      const res = await fn.call(kind === "pull" ? api.pulls : api.issues, { ...params, request: signal ? { signal } : undefined });
      return shape(res && res.data !== undefined ? res.data : res);
    };
  } else {
    const f = resolveFetch(fetchImpl);
    const url = String(apiBase).replace(/\/+$/, "") + "/repos/" + owner + "/" + repo + (kind === "pull" ? "/pulls/" : "/issues/") + number;
    const headers = {
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "intentrax-readback",
    };
    if (token) headers.authorization = "Bearer " + token;
    read = async ({ signal }) => {
      const { notFound, body } = await getJson({ fetchImpl: f, url, headers, signal, source: "GitHub", allowNotFound: notFoundAs !== undefined });
      if (notFound) return structuredClone(notFoundAs);
      return shape(body);
    };
  }

  return defineRecipe({
    href: import.meta.url,
    exportName: "githubIssue",
    options: opts,
    secrets: token ? [token] : [],
    resource: (kind === "pull" ? "pull request " : "issue ") + owner + "/" + repo + "#" + number,
    source: "GitHub",
    pending: null,
    read,
  });
}
