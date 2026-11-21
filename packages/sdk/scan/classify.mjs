// Heuristic classification of agent-reachable actions by the verbs in their
// names and descriptions, the side effects visible in their handlers, and
// (untrusted) MCP annotations. Every result carries `heuristic: true` and the
// reasons it was reached, because a name is not a behaviour.

import { tokenize } from "./text.mjs";

// severity 3: hard or impossible to undo; 2: consequential and visible to
// others; 1: changes state. 0: read-only or unclassified.
export const CATEGORIES = Object.freeze({
  destructive: { severity: 3, label: "destructive" },
  financial: { severity: 3, label: "moves money" },
  shell: { severity: 3, label: "runs shell commands" },
  database: { severity: 3, label: "can run arbitrary SQL" },
  infrastructure: { severity: 3, label: "changes infrastructure" },
  deploy: { severity: 2, label: "deploys, merges or publishes" },
  communication: { severity: 2, label: "sends messages" },
  access: { severity: 2, label: "changes access" },
  browser: { severity: 2, label: "acts in a browser" },
  write: { severity: 1, label: "writes data" },
  unknown: { severity: 1, label: "tools not listed statically" },
  read: { severity: 0, label: "read-only" },
  unclassified: { severity: 0, label: "unclassified" },
});

const VERBS = [
  ["destructive", ["delete", "del", "remove", "rm", "drop", "destroy", "purge", "truncate", "wipe", "erase", "terminate", "kill", "deprovision", "teardown", "nuke", "reset", "overwrite", "revoke", "uninstall", "cancel", "archive", "unlink", "rmdir", "shred", "flush", "evict"]],
  ["financial", ["refund", "payment", "transfer", "pay", "payout", "charge", "withdraw", "wire", "purchase", "buy", "sell", "trade", "swap", "capture", "settle", "disburse", "invoice", "bill", "checkout", "debit", "credit", "remit"]],
  ["shell", ["bash", "shell", "exec", "terminal", "cmd", "powershell", "sh", "zsh", "subprocess", "eval"]],
  ["deploy", ["deploy", "release", "publish", "rollback", "promote", "merge", "push", "apply", "scale", "restart", "provision", "migrate", "rebase", "tag", "redeploy", "shutdown", "reboot", "stop", "start"]],
  ["communication", ["send", "email", "mail", "post", "message", "notify", "sms", "tweet", "reply", "dm", "broadcast", "text", "call", "comment", "forward"]],
  ["access", ["grant", "invite", "permit", "authorize", "promote", "assign", "share", "impersonate", "rotate"]],
  ["write", ["write", "update", "create", "insert", "upsert", "edit", "modify", "set", "patch", "put", "save", "commit", "rename", "move", "upload", "approve", "execute", "run", "add", "append", "import", "sync", "submit", "change", "replace", "store", "enable", "disable", "close", "open", "book", "order", "schedule"]],
];

const READ_VERBS = new Set([
  "get", "list", "read", "search", "fetch", "query", "describe", "show", "find", "view", "lookup", "inspect",
  "status", "count", "check", "browse", "retrieve", "download", "explain", "preview", "validate", "verify",
  "diff", "ls", "cat", "head", "tail", "grep", "summarize", "summarise", "analyze", "analyse", "compare",
  "estimate", "quote", "ping", "health", "whoami", "info", "watch", "poll", "load", "lint", "parse",
]);

// Objects that turn "run"/"execute" into a shell or SQL action.
const SHELL_OBJECTS = new Set(["command", "commands", "shell", "bash", "script", "code", "terminal", "cmd", "process", "python", "powershell", "subprocess", "program"]);
const SQL_OBJECTS = new Set(["sql", "statement", "ddl", "dml"]);

const NEGATIONS = new Set(["not", "never", "no", "without", "cannot", "can't", "won't", "doesn't", "don't", "nothing", "non", "neither", "nor"]);

const VERB_INDEX = new Map();
for (const [category, verbs] of VERBS) {
  for (const v of verbs) if (!VERB_INDEX.has(v)) VERB_INDEX.set(v, category);
}

function stems(token) {
  const out = [token];
  if (token.endsWith("ing")) out.push(token.slice(0, -3), token.slice(0, -3) + "e");
  if (token.endsWith("ed")) out.push(token.slice(0, -2), token.slice(0, -1));
  if (token.endsWith("es")) out.push(token.slice(0, -2));
  if (token.endsWith("s")) out.push(token.slice(0, -1));
  return out;
}

function verbCategory(token) {
  for (const s of stems(token)) {
    if (VERB_INDEX.has(s)) return { category: VERB_INDEX.get(s), verb: s };
  }
  return null;
}

function isReadVerb(token) {
  return stems(token).some((s) => READ_VERBS.has(s));
}

function sev(category) {
  return CATEGORIES[category]?.severity ?? 0;
}

// Words that are verbs in "post_tweet" but nouns in "blog_post": they count
// only as the first word of a name.
const NOUN_LIKE = new Set([
  "post", "message", "email", "mail", "text", "call", "comment", "tag", "order", "book", "schedule", "credit",
  "bill", "invoice", "sms", "dm", "start", "stop", "open", "close", "set", "share", "change", "store", "archive",
  "transfer", "charge", "wire", "trade", "swap", "capture", "settle", "push", "apply", "scale", "release",
  "forward", "reply", "run", "import", "sync", "cancel", "flush", "promote", "rotate", "debit", "checkout",
  "payout", "refund", "payment", "purchase", "commit", "merge", "deploy", "publish",
]);

// "issue_refund", "make_payment", "trigger_deploy": the second word is the verb.
const LIGHT_VERBS = new Set(["issue", "make", "initiate", "trigger", "perform", "process", "do", "request", "force", "batch", "bulk", "auto", "mass"]);

function runLike(t, next) {
  if (!["run", "execute", "exec", "eval", "raw"].includes(t)) return null;
  const sql = next.find((n) => SQL_OBJECTS.has(n));
  if (sql) return { category: "database", verb: `${t} ${sql}` };
  const sh = next.find((n) => SHELL_OBJECTS.has(n));
  if (sh) return { category: "shell", verb: `${t} ${sh}` };
  return null;
}

// Tool names: "delete_volume", "volumeDelete", "get_refund", "list_deleted".
// A read verb anywhere in the name makes it read-only unless the name also
// carries a plain destructive verb or a run-SQL/run-shell pair.
function fromNameTokens(tokens) {
  const readVerb = tokens.find(isReadVerb);
  const hits = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    const special = runLike(t, tokens.slice(i + 1, i + 3));
    if (special) {
      hits.push(special);
      continue;
    }
    if (SQL_OBJECTS.has(t) && tokens.length <= 2 && !readVerb) {
      hits.push({ category: "database", verb: t });
      continue;
    }
    const hit = verbCategory(t);
    if (!hit) continue;
    if (readVerb) {
      // "get_refund", "list_transfers", "list_deleted_items" stay read-only.
      if (hit.category === "destructive" && t === hit.verb) hits.push(hit);
      continue;
    }
    if (NOUN_LIKE.has(hit.verb) && i !== 0 && !(i === 1 && LIGHT_VERBS.has(tokens[0]))) continue;
    hits.push(hit);
  }
  if (hits.length === 0) return readVerb ? { category: "read", verb: readVerb } : null;
  return hits.reduce((best, h) => (sev(h.category) > sev(best.category) ? h : best), hits[0]);
}

// Descriptions: highest-severity verb in the first 300 characters, skipping
// negated ones ("does not delete").
function fromDescriptionTokens(tokens) {
  let best = null;
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens.slice(Math.max(0, i - 3), i).some((p) => NEGATIONS.has(p))) continue;
    const hit = runLike(tokens[i], tokens.slice(i + 1, i + 3)) ?? verbCategory(tokens[i]);
    if (hit && !NOUN_LIKE.has(hit.verb) && (!best || sev(hit.category) > sev(best.category))) best = hit;
  }
  return best;
}

// Side effects visible in a handler body. Order matters: first match per
// category wins; we report the strongest.
const SIDE_EFFECTS = [
  { category: "destructive", re: /\b(?:DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW)|TRUNCATE\s+(?:TABLE\s+)?\w)/i, what: "SQL DELETE/DROP/TRUNCATE" },
  { category: "destructive", re: /\.(?:delete|destroy|remove|deleteMany|deleteOne|drop|terminate|purge)\w*\s*\(/, what: "a delete/destroy call", weak: true },
  { category: "destructive", re: /\brm\s+-[a-z]*r|\brmSync\s*\(|\bunlinkSync\s*\(|\bunlink\s*\(|shutil\.rmtree|os\.remove\s*\(|os\.unlink\s*\(/, what: "a file deletion" },
  { category: "destructive", re: /method\s*[:=]\s*["']DELETE["']/i, what: "an HTTP DELETE" },
  { category: "financial", re: /\b(?:refunds|transfers|payouts|charges|paymentIntents|payment_intents)\.(?:create|confirm|capture)\b|\bRefund\.create\b|\bTransfer\.create\b/, what: "a payment API call" },
  { category: "shell", re: /\bchild_process\b|\b(?:execSync|execFileSync|execFile|spawnSync)\s*\(|(?<![.\w$])exec\s*\(|\b(?:cp|childProcess)\.exec\s*\(|(?<![.\w$])spawn\s*\(|\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b|\bos\.system\s*\(|shell\s*=\s*True/, what: "a shell/process execution" },
  { category: "communication", re: /\b(?:sendMail|sendEmail|send_email|send_mail)\s*\(|\.messages\.send\b|chat\.postMessage|chat_postMessage|\btwilio\b|\bses\.send|\bresend\.emails\b|\bsendgrid\b/i, what: "a message-sending call" },
  { category: "deploy", re: /\bgit\s+push\b|\bkubectl\s+(?:apply|delete|scale|rollout)|\bterraform\s+(?:apply|destroy)|\bhelm\s+(?:install|upgrade|uninstall)/, what: "a deploy/infra command" },
  { category: "write", re: /\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b/i, what: "SQL INSERT/UPDATE" },
  { category: "write", re: /method\s*[:=]\s*["'](?:POST|PUT|PATCH)["']/i, what: "an HTTP POST/PUT/PATCH" },
];

export function sideEffectsIn(body) {
  const hits = [];
  for (const se of SIDE_EFFECTS) {
    const m = se.re.exec(body ?? "");
    if (m) hits.push({ category: se.category, what: se.what, index: m.index, weak: Boolean(se.weak) });
  }
  return hits;
}

// Every side-effect occurrence, in source order. Used where ordering matters
// (a read-back must follow the LAST mutation, not the first of each kind).
export function allSideEffectsIn(body) {
  const hits = [];
  const text = body ?? "";
  for (const se of SIDE_EFFECTS) {
    const re = new RegExp(se.re.source, se.re.flags.includes("g") ? se.re.flags : `${se.re.flags}g`);
    let m;
    while ((m = re.exec(text))) {
      hits.push({ category: se.category, what: se.what, index: m.index, weak: Boolean(se.weak) });
      if (m[0].length === 0) re.lastIndex += 1;
    }
  }
  return hits.sort((a, b) => a.index - b.index);
}

// Classifies one action. Inputs are names, a description and a handler body;
// none of them is printed back (only the matched verb).
export function classifyAction({ name, description = "", body = "", annotations = {}, domainTokens = null }) {
  const reasons = [];
  const nameTokens = tokenize(name);
  let result = null;

  const fromName = fromNameTokens(nameTokens);
  if (fromName && fromName.category === "read") {
    result = "read";
    reasons.push(`name contains the read verb "${fromName.verb}"`);
  } else if (fromName) {
    result = fromName.category;
    reasons.push(`name contains "${fromName.verb}"`);
  } else if (description) {
    const fromDesc = fromDescriptionTokens(tokenize(String(description).slice(0, 300)));
    if (fromDesc) {
      result = fromDesc.category;
      reasons.push(`description contains "${fromDesc.verb}"`);
    }
  }

  // Handler side effects can upgrade, never downgrade.
  for (const se of sideEffectsIn(body)) {
    // A generic ".delete(" (often a Map or cache) does not overrule a read name.
    if (se.weak && result === "read") continue;
    if (!result || sev(se.category) > sev(result)) {
      reasons.push(`handler contains ${se.what}`);
      result = se.category;
    }
  }

  // Domain words (external MCP servers whose tools cannot be listed).
  if (domainTokens) {
    const d = domainCategory(domainTokens);
    if (d && (!result || sev(d.category) > sev(result))) {
      result = d.category;
      reasons.push(`server name or launch command mentions "${d.word}"; its tools could not be listed statically`);
    }
  }

  // MCP annotations are self-declared by the server, so they are untrusted:
  // they may raise our concern but never lower it.
  if (annotations.destructiveHint === true) {
    if (sev(result) < 3) {
      result = "destructive";
      reasons.push("annotation destructiveHint=true (self-declared by the server; read as a warning, never as reassurance)");
    } else {
      reasons.push("annotation destructiveHint=true agrees (self-declared, untrusted)");
    }
  } else if (annotations.destructiveHint === false && sev(result) >= 3) {
    reasons.push("annotation destructiveHint=false ignored: annotations are untrusted");
  }
  if (annotations.readOnlyHint === true && sev(result) > 0) {
    reasons.push("annotation readOnlyHint=true ignored: annotations are untrusted");
  }

  if (!result) {
    result = "unclassified";
    reasons.push("no consequential verb in the name or description");
  }
  return {
    category: result,
    label: CATEGORIES[result].label,
    severity: sev(result),
    consequential: sev(result) > 0,
    heuristic: true,
    reasons,
  };
}

const DOMAINS = [
  ["shell", ["shell", "terminal", "commander", "bash", "cmd", "ssh", "exec", "powershell", "zsh"]],
  ["database", ["postgres", "postgresql", "pg", "mysql", "mariadb", "sqlite", "sql", "mssql", "mongo", "mongodb", "redis", "supabase", "neon", "database", "db", "prisma", "planetscale", "dynamodb", "firestore", "bigquery", "snowflake", "clickhouse"]],
  ["infrastructure", ["aws", "gcp", "gcloud", "azure", "kubernetes", "k8s", "kubectl", "terraform", "railway", "vercel", "netlify", "fly", "heroku", "cloudflare", "digitalocean", "docker", "render", "pulumi", "ec2", "s3", "lambda", "infra"]],
  ["financial", ["stripe", "paypal", "square", "plaid", "braintree", "adyen", "payment", "payments", "billing", "bank", "banking", "ledger", "wise", "coinbase"]],
  ["deploy", ["github", "gitlab", "bitbucket", "git", "jenkins", "circleci", "argocd", "deploy"]],
  ["communication", ["slack", "gmail", "email", "mail", "twilio", "sendgrid", "discord", "telegram", "teams", "outlook", "resend", "whatsapp", "mailgun", "postmark", "intercom", "zendesk"]],
  ["browser", ["puppeteer", "playwright", "browser", "chrome", "selenium", "browserbase"]],
  ["write", ["filesystem", "fs", "files", "drive", "gdrive", "dropbox", "onedrive", "box", "notion", "jira", "linear", "airtable", "sheets", "hubspot", "salesforce", "shopify"]],
];

export function domainCategory(tokens) {
  let best = null;
  for (const [category, words] of DOMAINS) {
    const word = tokens.find((t) => words.includes(t));
    if (word && (!best || sev(category) > sev(best.category))) best = { category, word };
  }
  return best;
}

export function isReadOnlyClassification(c) {
  return c.category === "read";
}
