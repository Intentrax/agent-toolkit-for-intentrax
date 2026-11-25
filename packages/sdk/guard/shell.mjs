// Shell-command classification for `intentrax guard`.
//
// Claude Code's Bash and PowerShell tools hand the hook a command line. This
// module splits it into simple commands (on ; && || | & and newlines, plus
// $(...), backticks and `sh -c '...'` bodies), strips wrappers such as sudo,
// env assignments and xargs, and classifies each one. The strictest verdict
// wins.
//
// Heuristic by design: it reads the text of a command and never runs it. It
// can be evaded by an agent that obfuscates a command (base64, variables
// built at run time), which is why block-class patterns are a floor and not a
// sandbox. Verdicts: "block" (deny), "ask" (Claude Code asks the user),
// "allow" (no objection: the call goes through Claude Code's own permission
// rules unchanged).

import { posix } from "node:path";

export const VERDICT_RANK = Object.freeze({ allow: 0, ask: 1, block: 2 });

export function stricter(a, b) {
  if (!a) return b;
  if (!b) return a;
  return VERDICT_RANK[b.verdict] > VERDICT_RANK[a.verdict] ? b : a;
}

const MAX_DEPTH = 4;
const MAX_SEGMENTS = 400;

// Split a command line into top-level simple commands. Quotes are respected;
// $(...) and backtick bodies are returned as extra command lines to classify.
export function splitCommandLine(text) {
  const segments = [];
  const nested = [];
  let cur = "";
  let quote = null;
  const s = String(text ?? "");
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (quote) {
      if (c === "\\" && quote === '"' && i + 1 < s.length) {
        cur += c + s[i + 1];
        i += 1;
        continue;
      }
      if (c === quote) quote = null;
      if (quote === '"' && c === "$" && s[i + 1] === "(") {
        const end = matchParen(s, i + 1);
        nested.push(s.slice(i + 2, end));
        cur += s.slice(i, end + 1);
        i = end;
        continue;
      }
      if (quote === '"' && c === "`") {
        const end = s.indexOf("`", i + 1);
        const stop = end < 0 ? s.length : end;
        nested.push(s.slice(i + 1, stop));
        cur += s.slice(i, stop + 1);
        i = stop;
        continue;
      }
      cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if (c === "\\" && i + 1 < s.length) {
      cur += c + s[i + 1];
      i += 1;
      continue;
    }
    if (c === "$" && s[i + 1] === "(") {
      const end = matchParen(s, i + 1);
      nested.push(s.slice(i + 2, end));
      cur += s.slice(i, end + 1);
      i = end;
      continue;
    }
    if (c === "`") {
      const end = s.indexOf("`", i + 1);
      const stop = end < 0 ? s.length : end;
      nested.push(s.slice(i + 1, stop));
      cur += s.slice(i, stop + 1);
      i = stop;
      continue;
    }
    if (c === "(" || c === ")" || c === "{" || c === "}") {
      // Subshells and groups: treat as separators (the body is still split).
      if (c === "{" || c === "}") {
        // `${VAR}` stays a word.
        if (c === "{" && s[i - 1] === "$") {
          cur += c;
          continue;
        }
        if (c === "}" && /\$\{[^}]*$/.test(cur)) {
          cur += c;
          continue;
        }
      }
      if (c === "(" && s[i - 1] === "<") {
        // process substitution <(...)
        const end = matchParen(s, i);
        nested.push(s.slice(i + 1, end));
        i = end;
        continue;
      }
      push();
      continue;
    }
    if (c === ";" || c === "\n" || c === "\r" || c === "|" || c === "&") {
      if ((c === "&" && (s[i - 1] === ">" || s[i + 1] === ">")) || (c === "|" && s[i - 1] === ">")) {
        // 2>&1, &>file, >|file (noclobber override) are redirections, not
        // separators
        cur += c; // 2>&1, &>file
        continue;
      }
      push();
      continue;
    }
    cur += c;
  }
  push();
  return { segments, nested };

  function push() {
    const t = cur.trim();
    if (t) segments.push(t);
    cur = "";
  }
}

function matchParen(s, openIndex) {
  let depth = 0;
  let quote = null;
  for (let i = openIndex; i < s.length; i += 1) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === "(") depth += 1;
    else if (c === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return s.length - 1;
}

// Shell words of one simple command, with quotes removed.
// The body of a bash $'…' string starting at `start` (after the quote), with
// its escapes decoded. Returns { text, end } where `end` is the index of the
// closing quote (or the last index when unterminated).
function ansiC(s, start) {
  const simple = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };
  let text = "";
  let i = start;
  for (; i < s.length; i += 1) {
    const c = s[i];
    if (c === "'") return { text, end: i };
    if (c !== "\\" || i + 1 >= s.length) {
      text += c;
      continue;
    }
    const n = s[i + 1];
    if (Object.hasOwn(simple, n)) {
      text += simple[n];
      i += 1;
    } else if (n === "x" && /^[0-9A-Fa-f]{1,2}/.test(s.slice(i + 2))) {
      const hex = /^[0-9A-Fa-f]{1,2}/.exec(s.slice(i + 2))[0];
      text += String.fromCharCode(parseInt(hex, 16));
      i += 1 + hex.length;
    } else if (/[0-7]/.test(n)) {
      const oct = /^[0-7]{1,3}/.exec(s.slice(i + 1))[0];
      text += String.fromCharCode(parseInt(oct, 8));
      i += oct.length;
    } else if ((n === "u" || n === "U") && /^[0-9A-Fa-f]{1,8}/.test(s.slice(i + 2))) {
      const hex = /^[0-9A-Fa-f]{1,8}/.exec(s.slice(i + 2))[0].slice(0, n === "u" ? 4 : 8);
      text += String.fromCodePoint(parseInt(hex, 16));
      i += 1 + hex.length;
    } else {
      text += "\\" + n;
      i += 1;
    }
  }
  return { text, end: s.length - 1 };
}

export function words(segment) {
  const out = [];
  let cur = "";
  let has = false;
  let quote = null;
  for (let i = 0; i < segment.length; i += 1) {
    const c = segment[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && i + 1 < segment.length && /["\\$`]/.test(segment[i + 1])) {
        cur += segment[i + 1];
        i += 1;
      } else cur += c;
      continue;
    }
    if (c === "$" && segment[i + 1] === "'") {
      // ANSI-C quoting: $'DROP\tTABLE users'
      const { text, end } = ansiC(segment, i + 2);
      cur += text;
      has = true;
      i = end;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      has = true;
      continue;
    }
    if (c === "\\" && i + 1 < segment.length) {
      cur += segment[i + 1];
      has = true;
      i += 1;
      continue;
    }
    if (/\s/.test(c)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
      continue;
    }
    cur += c;
    has = true;
  }
  if (has || cur) out.push(cur);
  return out;
}

const WRAPPERS = new Set(["sudo", "doas", "nohup", "time", "command", "builtin", "exec", "nice", "ionice", "stdbuf", "timeout", "caffeinate", "watch", "then", "do", "else", "!", "eval"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "powershell.exe", "pwsh.exe", "cmd", "cmd.exe"]);

function base(cmd) {
  const b = String(cmd).replace(/\\/g, "/").split("/").pop().toLowerCase();
  return b.endsWith(".exe") ? b.slice(0, -4) : b;
}

// Strip env assignments and wrapper commands. Returns { argv, inner } where
// `inner` is a command line to classify recursively (sh -c '...', xargs X).
function unwrap(argv) {
  let a = [...argv];
  for (let guard = 0; guard < 10 && a.length; guard += 1) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a[0])) {
      a = a.slice(1);
      continue;
    }
    const b = base(a[0]);
    if (b === "env") {
      a = a.slice(1);
      while (a.length && (a[0].startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(a[0]))) a = a.slice(1);
      continue;
    }
    if (b === "eval") return { argv: a, inner: a.slice(1).join(" ") };
    if (WRAPPERS.has(b)) {
      a = a.slice(1);
      // timeout 10 cmd / nice -n 5 cmd / sudo -u x cmd
      while (a.length && (a[0].startsWith("-") || /^\d+[smhd]?$/.test(a[0]))) {
        if (["-u", "-g", "-n", "-c", "-k", "-s"].includes(a[0]) && a.length > 1 && !a[1].startsWith("-")) a = a.slice(1);
        a = a.slice(1);
      }
      continue;
    }
    if (b === "npx" || b === "bunx" || b === "pnpx" || ((b === "pnpm" || b === "yarn") && a[1] === "dlx") || (b === "npm" && a[1] === "exec")) {
      a = a.slice(b === "npx" || b === "bunx" || b === "pnpx" ? 1 : 2);
      while (a.length && a[0].startsWith("-")) {
        if (["-p", "--package", "-c", "--call"].includes(a[0])) a = a.slice(1);
        a = a.slice(1);
      }
      if (a[0] === "--") a = a.slice(1);
      // `npx @scope/pkg@1 cmd` runs the package's bin: keep the package name as argv0
      // but drop a version suffix so tables match `prisma`, `vercel`, ...
      if (a.length) a = [a[0].replace(/^(@[^/]+\/)?([^@]+)@.*$/, "$1$2"), ...a.slice(1)];
      continue;
    }
    if (b === "xargs") {
      a = a.slice(1);
      while (a.length && a[0].startsWith("-")) {
        if (["-I", "-n", "-P", "-L", "-d", "-E", "-s"].includes(a[0])) a = a.slice(1);
        a = a.slice(1);
      }
      continue;
    }
    if (SHELLS.has(b)) {
      const ci = a.findIndex((w, i) => i > 0 && /^(-c|-lc|-ic|-command|\/c|-c\b.*)$/i.test(w));
      if (ci > 0 && a[ci + 1] !== undefined) return { argv: a, inner: a.slice(ci + 1).join(" ") };
      // `bash script.sh`, `curl ... | sh`: no inline body.
      return { argv: a, inner: null };
    }
    break;
  }
  return { argv: a, inner: null };
}

const CATASTROPHIC_RM_TARGETS = /^(?:\/|\/\*|~|~\/|~\/\*|\$HOME|\$\{HOME\}|\$HOME\/\*?|\.|\.\/|\.\.|\.\.\/|\*|\.\/\*|[A-Za-z]:[\\/]?|[A-Za-z]:[\\/]\*|\/(?:bin|boot|dev|etc|home|lib|lib64|opt|proc|root|sbin|srv|sys|usr|var|Users|System|Library|Applications)(?:\/\*?)?)$/;

function rmFlags(args) {
  let recursive = false;
  let force = false;
  let noPreserveRoot = false;
  const targets = [];
  let endOfOpts = false;
  for (const w of args) {
    if (!endOfOpts && w === "--") {
      endOfOpts = true;
      continue;
    }
    if (!endOfOpts && w.startsWith("--")) {
      if (w === "--recursive") recursive = true;
      if (w === "--force") force = true;
      if (w === "--no-preserve-root") noPreserveRoot = true;
      continue;
    }
    if (!endOfOpts && /^-[a-zA-Z]+$/.test(w)) {
      if (/[rR]/.test(w)) recursive = true;
      if (/f/.test(w)) force = true;
      continue;
    }
    targets.push(w);
  }
  return { recursive, force, noPreserveRoot, targets };
}

// Each keyword carries its own boundary; the table after TRUNCATE only has to
// start (bare, "quoted", `backticked` or [bracketed]), so `TRUNCATE users`
// and `TRUNCATE TABLE ONLY "a"."b"` both match.
const SQL_DESTRUCTIVE = /\b(?:DROP\s+(?:DATABASE|SCHEMA|TABLE|COLLECTION)\b|TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?[\\"`[\w]|FLUSHALL\b|FLUSHDB\b|dropDatabase\b)|\.drop(?:Database)?\s*\(/i;
// `DELETE FROM <table>` with no WHERE before the statement ends. The table
// name is consumed whole first: bare, "quoted" (also shell-escaped \"x\"),
// `backticked` or [bracketed], optionally schema-qualified, so the closing
// quote of `"users"` is never mistaken for the end of the statement. The
// statement ends at `;` or a quote that closes the shell argument. Newlines
// are whitespace, so a formatted `DELETE FROM t\nWHERE ...` keeps its WHERE.
const SQL_IDENT_PART = String.raw`(?:\\?"(?:[^"\\]|\\(?!"))*\\?"|` + "`[^`]*`" + String.raw`|\[[^\]]*\]|[A-Za-z_][\w$]*)`;
const SQL_DELETE_FROM = new RegExp(String.raw`\bDELETE\s+FROM\s+(?:ONLY\s+)?` + SQL_IDENT_PART + String.raw`(?:\s*\.\s*` + SQL_IDENT_PART + ")*", "gi");

export function deleteWithoutWhere(text) {
  const t = String(text ?? "");
  for (const m of t.matchAll(SQL_DELETE_FROM)) {
    if (!/\bWHERE\b/i.test(restOfStatement(t.slice(m.index + m[0].length)))) return true;
  }
  return false;
}

// The rest of one SQL statement, up to a top-level `;`, with string literals,
// quoted identifiers ("u", `u`, [u]) and -- / /* */ comments replaced by
// placeholders. So a quoted alias or a literal 'where' neither ends the scan
// nor counts as a WHERE clause. An unterminated quote runs to the end.
//
// Where dialects differ, the scan takes the reading that hides more text, so
// a mistake can only turn a scoped DELETE into a block, never an unscoped one
// into an ask: a backslash escapes the next character inside any quote
// (MySQL, Postgres E'…'), `$tag$ … $tag$` is a string (Postgres), `#` starts
// a comment (MySQL), and /* */ comments nest (Postgres).
//
// Hiding text is only safe if it cannot hide a statement boundary, so the
// statement ends at the FIRST `;`, even one inside a quote or comment, and a
// WHERE must come before it. The cost is a rare false block for a `;` inside
// a literal; the scan can never walk into the next statement's WHERE.
export function restOfStatement(input) {
  const semi = input.indexOf(";");
  const rest = semi < 0 ? input : input.slice(0, semi);
  let out = "";
  const quoted = (i, close) => {
    let j = i + 1;
    while (j < rest.length) {
      if (rest[j] === "\\") {
        j += 2;
        continue;
      }
      if (rest[j] === close) {
        if (close !== "]" && rest[j + 1] === close) {
          j += 2; // doubled quote inside the string
          continue;
        }
        return j + 1;
      }
      j += 1;
    }
    return rest.length; // unterminated: hides the rest
  };
  for (let i = 0; i < rest.length; ) {
    const c = rest[i];
    if (c === ";") break;
    if (c === "'") {
      out += " '' ";
      i = quoted(i, "'");
      continue;
    }
    if (c === '"' || c === "`" || c === "[") {
      out += " _ident_ ";
      i = quoted(i, c === "[" ? "]" : c);
      continue;
    }
    if (c === "$") {
      const tag = /^\$[A-Za-z_]*\$/.exec(rest.slice(i));
      if (tag) {
        const end = rest.indexOf(tag[0], i + tag[0].length);
        out += " '' ";
        i = end < 0 ? rest.length : end + tag[0].length;
        continue;
      }
    }
    if ((c === "-" && rest[i + 1] === "-") || c === "#") {
      const j = rest.indexOf("\n", i);
      i = j < 0 ? rest.length : j;
      continue;
    }
    if (c === "/" && rest[i + 1] === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < rest.length && depth > 0) {
        if (rest[j] === "/" && rest[j + 1] === "*") {
          depth += 1;
          j += 2;
        } else if (rest[j] === "*" && rest[j + 1] === "/") {
          depth -= 1;
          j += 2;
        } else j += 1;
      }
      i = j;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}
// Writes and schema changes that ask (the destructive ones above block).
// UPDATE ... SET spans any table form (quoted, bracketed, aliased, joined)
// within one statement; GRANT/REVOKE need their TO/FROM so prose does not
// trip them.
const SQL_WRITE = new RegExp([
  String.raw`\bDELETE\s+FROM\b`,
  String.raw`\bUPDATE\b[^;]{1,200}?\bSET\b`,
  String.raw`\b(?:INSERT|REPLACE|UPSERT|MERGE)\s+(?:OVERWRITE\s+|IGNORE\s+)?INTO\b`,
  String.raw`\bCOPY\b[^;]{1,200}?\bFROM\b`,
  String.raw`\bALTER\s+(?:TABLE|DATABASE|SCHEMA|USER|ROLE|INDEX|VIEW|SEQUENCE|TYPE)\b`,
  String.raw`\bDROP\s+(?:INDEX|VIEW|MATERIALIZED\s+VIEW|FUNCTION|PROCEDURE|TRIGGER|SEQUENCE|USER|ROLE|TYPE|EXTENSION)\b`,
  String.raw`\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|INDEX|UNIQUE\s+INDEX|USER|ROLE|VIEW|FUNCTION|PROCEDURE|TRIGGER|DATABASE|SCHEMA|EXTENSION)\b`,
  String.raw`\bGRANT\s+[^;]{1,200}?\bTO\b`,
  String.raw`\bREVOKE\s+[^;]{1,200}?\bFROM\b`,
  String.raw`\.(?:deleteMany|deleteOne|updateMany|updateOne|insertMany|insertOne|replaceOne|bulkWrite|remove)\s*\(`,
].join("|"), "i");
const DB_CLIENTS = new Set(["psql", "pg_restore", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo", "redis-cli", "cqlsh", "clickhouse-client", "bq", "snowsql", "cockroach", "supabase", "neonctl", "turso", "prisma", "pscale"]);
const PROD_HINT = /(?:^|[^a-z])(?:prod|production|live|primary)(?:[^a-z]|$)/i;

// Classify SQL text found anywhere (a db client's arguments, an MCP tool's
// input). Returns a decision or null.
// The texts to read as SQL from a database client's (shell-unquoted)
// arguments:
//   - each argument on its own, so two -c statements are judged separately;
//   - each argument with an attached option removed: `-c"DROP …"` arrives as
//     `-cDROP …`, `--command=DELETE …` as one word;
//   - all arguments joined, for clients that join positional words into one
//     query (`bq query DELETE FROM ds.t`).
// The strictest result over all of them wins.
export function sqlCandidates(args) {
  const out = [];
  for (const arg of args) {
    out.push(arg);
    const long = arg.replace(/^--?[A-Za-z][\w-]*=/, "");
    if (long !== arg) out.push(long);
    // `-c"…"`, `-Xc"…"`, `-sNe"…"`: up to four bundled short flags, each
    // length tried (the flags and the SQL are both letters, so the split
    // point is unknown).
    if (/^-[A-Za-z]/.test(arg) && !arg.startsWith("--")) {
      for (let k = 1; k <= 4 && /^[A-Za-z]$/.test(arg[k] ?? ""); k += 1) {
        if (arg.length > k + 1) out.push(arg.slice(k + 1));
      }
    }
  }
  if (args.length > 1) out.push(args.map((a) => a.replace(/^-[A-Za-z](?=\S)/, "").replace(/^--?[A-Za-z][\w-]*=/, "")).join(" "));
  return out;
}

export function classifySqlText(text, { prodHint = false } = {}) {
  const t = String(text ?? "");
  if (SQL_DESTRUCTIVE.test(t)) {
    return { verdict: "block", category: "database", rule: "sql-drop-truncate", reason: "drops or truncates a database object (DROP/TRUNCATE/FLUSHALL)" };
  }
  if (deleteWithoutWhere(t)) {
    return { verdict: "block", category: "database", rule: "sql-delete-without-where", reason: "DELETE without a WHERE clause removes every row" };
  }
  if (SQL_WRITE.test(t)) {
    if (prodHint) return { verdict: "block", category: "database", rule: "sql-write-production", reason: "writes to what looks like a production database" };
    return { verdict: "ask", category: "database", rule: "sql-write", reason: "writes to a database (DELETE/UPDATE/INSERT/ALTER)" };
  }
  return null;
}

// The guard's own files (hook runtime, record, keys, guard rules), the pack
// policy it evaluates and the MCP pins the proxy enforces. Writing to them from
// the agent would switch protection off or rewrite the record: blocked.
export const GUARD_PROTECTED = [
  /\.intentrax[\\/]+guard(?:[\\/]|$)/i,
  /\.intentrax[\\/]+(?:policy\.jsonc|mcp-pins\.json)(?![\w.-])/i,
];
// The Claude Code settings that load the hook, and .mcp.json, which routes MCP
// servers through the pinning proxy. Users legitimately ask the agent to edit
// these, so a change asks (you see the diff) instead of blocking.
export const CLAUDE_SETTINGS = [
  /\.claude[\\/]+settings(?:\.local)?\.json/i,
  /(?:^|[\\/\s"'=>])\.mcp\.json(?![\w.-])/i,
];
const READ_ONLY_CMDS = new Set(["cat", "less", "more", "head", "tail", "ls", "dir", "stat", "file", "wc", "grep", "rg", "ag", "jq", "diff", "type", "get-content", "gc", "select-string", "sha256sum", "shasum", "md5sum", "git", "find", "tree", "code", "open", "echo", "printf", "test", "["]);

// The command text with each word's path normalised (quotes removed, `\` as
// `/`, `.` and `..` segments folded), so `.intentrax/./guard` or
// `.intent"rax"/guard` match like the plain path.
function normalisedText(segment) {
  return words(segment).map((w) => (/[\\/]/.test(w) ? posix.normalize(w.replace(/\\/g, "/")) : w)).join(" ");
}

// An output redirection to a file, with or without a file descriptor:
// `>`, `>>`, `1>`, `2>>`, `&>`, `&>>`, `>|`, `1>|`. Duplicating a descriptor
// (`2>&1`, `>&2`, `>&-`) writes no file and does not count.
export const FILE_REDIRECT = /(?:\d*|&)>>?\|?(?!&(?:\d|-))/;

// True when one simple command only reads: a read-only program, no output
// redirection, no in-place edit, no git or find that changes files.
export function isReadOnlySegment(segment) {
  const { argv } = unwrap(words(segment));
  if (argv.length === 0) return true;
  const b = base(argv[0]);
  const args = argv.slice(1);
  if (!READ_ONLY_CMDS.has(b)) return false;
  if (FILE_REDIRECT.test(segment)) return false;
  if ((b === "sed" || b === "perl") && args.some((a) => /^-[a-zA-Z]*i/.test(a))) return false;
  if (b === "git" && /\b(?:rm|mv|checkout|restore|reset|clean|apply|am|stash)\b/.test(segment)) return false;
  if (b === "find" && /-delete|-exec/.test(segment)) return false;
  return true;
}

function writesTo(patterns, b, args, rawText) {
  const norm = normalisedText(rawText);
  const text = patterns.some((re) => re.test(rawText)) ? rawText : norm;
  if (!patterns.some((re) => re.test(text))) return false;
  const redirect = patterns.some((re) => new RegExp(FILE_REDIRECT.source + String.raw`\s*\S*` + re.source, "i").test(text));
  const sedInPlace = (b === "sed" || b === "perl") && args.some((a) => /^-[a-zA-Z]*i/.test(a));
  return redirect || sedInPlace || !READ_ONLY_CMDS.has(b) || (b === "git" && /\b(?:rm|mv|checkout|restore|reset|clean)\b/.test(text)) || (b === "find" && /-delete|-exec/.test(text));
}

const D = (verdict, category, rule, reason) => ({ verdict, category, rule, reason });

function hasFlag(args, ...flags) {
  return args.some((a) => flags.includes(a) || flags.some((f) => f.startsWith("--") && a.startsWith(f + "=")));
}

function shortFlag(args, letter) {
  return args.some((a) => /^-[a-zA-Z]+$/.test(a) && a.includes(letter));
}

function classifyGit(args) {
  // skip global options: git -C dir, -c k=v
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) i += ["-C", "-c", "--git-dir", "--work-tree"].includes(args[i]) ? 2 : 1;
  const sub = args[i];
  const rest = args.slice(i + 1);
  switch (sub) {
    case "push": {
      if (hasFlag(rest, "--force", "--mirror") || shortFlag(rest, "f") || rest.some((a) => /^\+[^+]/.test(a))) {
        return D("block", "deploy", "git-force-push", "force-pushes, which can overwrite other people's commits on the remote");
      }
      if (hasFlag(rest, "--force-with-lease", "--force-if-includes")) return D("ask", "deploy", "git-force-with-lease", "force-pushes with a lease (rewrites remote history)");
      if (hasFlag(rest, "--delete") || shortFlag(rest, "d") || rest.some((a) => /^:[^:]/.test(a))) return D("ask", "deploy", "git-push-delete", "deletes a remote branch or tag");
      return D("ask", "deploy", "git-push", "pushes commits to a remote");
    }
    case "reset":
      if (hasFlag(rest, "--hard", "--merge", "--keep")) return D("ask", "destructive", "git-reset-hard", "discards uncommitted work (git reset --hard)");
      return null;
    case "clean":
      if (shortFlag(rest, "f") || hasFlag(rest, "--force")) return D("ask", "destructive", "git-clean", "deletes untracked files (git clean -f)");
      return null;
    case "checkout":
    case "restore":
      if (rest.includes("--") && rest.slice(rest.indexOf("--") + 1).some((a) => a === "." || a === "*" || a === ":/")) return D("ask", "destructive", "git-discard-changes", "discards uncommitted changes in the working tree");
      if (sub === "restore" && rest.some((a) => a === "." || a === ":/") && !hasFlag(rest, "--staged")) return D("ask", "destructive", "git-discard-changes", "discards uncommitted changes in the working tree");
      return null;
    case "branch":
      if (rest.includes("-D") || (hasFlag(rest, "--delete") && hasFlag(rest, "--force"))) return D("ask", "destructive", "git-branch-force-delete", "force-deletes a branch");
      return null;
    case "stash":
      if (rest[0] === "clear" || rest[0] === "drop") return D("ask", "destructive", "git-stash-drop", "drops stashed work");
      return null;
    case "filter-branch":
    case "filter-repo":
      return D("ask", "destructive", "git-rewrite-history", "rewrites repository history");
    case "reflog":
      if (rest[0] === "expire" || rest[0] === "delete") return D("ask", "destructive", "git-reflog-expire", "expires reflog entries (removes the recovery path)");
      return null;
    case "update-ref":
      if (shortFlag(rest, "d")) return D("ask", "destructive", "git-update-ref-delete", "deletes a ref");
      return null;
    default:
      return null;
  }
}

const PUBLISH = [
  [/^(?:npm|pnpm|yarn|bun)$/, (a) => a[0] === "publish" || (a[0] === "npm" && a[1] === "publish") || a.includes("publish") && a[0] !== "run", "package-publish", "publishes a package to a registry"],
  [/^(?:cargo|twine|gem|poetry|flit|hatch|dotnet|nuget|mvn|gradle)$/, (a) => a.some((w) => ["publish", "upload", "push", "deploy"].includes(w)), "package-publish", "publishes a package to a registry"],
  [/^docker$|^podman$/, (a) => a[0] === "push" || (a[0] === "image" && a[1] === "push"), "image-push", "pushes a container image"],
  [/^gh$/, (a) => (a[0] === "pr" && a[1] === "merge") || (a[0] === "release" && ["create", "delete", "upload", "edit"].includes(a[1])) || (a[0] === "repo" && ["delete", "archive", "rename", "edit"].includes(a[1])) || (a[0] === "workflow" && a[1] === "run") || (a[0] === "api" && a.some((w) => /^-X$|^--method$/.test(w))), "github-write", "changes GitHub state (merge, release, repo settings or API write)"],
  [/^(?:vercel|netlify|firebase|fly|flyctl|railway|heroku|wrangler|serverless|sls|amplify|eb|cdk|sam|render|surge|now)$/, (a) => a.some((w) => ["deploy", "up", "--prod", "publish", "promote", "release", "rollback", "scale", "restart"].includes(w)), "deploy", "deploys or changes a hosted service"],
  [/^kubectl$|^oc$/, (a) => ["apply", "create", "replace", "patch", "scale", "rollout", "set", "edit", "annotate", "label", "drain", "cordon", "taint", "exec", "cp", "delete"].includes(a[0]), "kubectl-write", "changes or deletes Kubernetes resources"],
  [/^helm$/, (a) => ["install", "upgrade", "rollback", "uninstall", "delete"].includes(a[0]), "helm-write", "changes a Kubernetes release"],
  [/^(?:terraform|tofu|pulumi|terragrunt)$/, (a) => ["apply", "import", "taint", "untaint", "up", "refresh", "state"].includes(a[0]), "iac-apply", "applies infrastructure changes"],
  [/^ansible-playbook$/, () => true, "ansible", "runs an Ansible playbook against hosts"],
  [/^(?:sendmail|mail|mailx|mutt|msmtp|swaks)$/, () => true, "send-email", "sends email"],
  [/^stripe$/, (a) => a.some((w) => /^(?:create|update|delete|capture|cancel|refund|confirm|pay|void|post)$/.test(w)) || a.some((w) => /^(?:refunds|charges|payouts|transfers|payment_intents|subscriptions|invoices)$/.test(w)) && !a.includes("list") && !a.includes("retrieve"), "payment", "changes payments or billing (Stripe)"],
  [/^ssh$|^scp$|^rsync$|^sftp$/, () => true, "remote-shell", "runs commands on or copies files to another machine"],
];

const INFRA_DESTROY = [
  [/^(?:terraform|tofu|terragrunt)$/, (a) => a[0] === "destroy" || (a[0] === "apply" && a.includes("-destroy")), "iac-destroy", "destroys infrastructure (terraform destroy)"],
  [/^pulumi$/, (a) => a[0] === "destroy" || (a[0] === "stack" && a[1] === "rm"), "iac-destroy", "destroys infrastructure (pulumi destroy)"],
  [/^kubectl$|^oc$/, (a) => a[0] === "delete" && (a.some((w) => /^(?:ns|namespaces?|nodes?|pv|persistentvolumes?|pvc|persistentvolumeclaims?|crd|customresourcedefinitions?|clusterroles?)$/.test(w)) || a.includes("--all") || a.includes("-A") || a.includes("--all-namespaces")), "kubectl-delete-wide", "deletes namespaces, volumes or every resource of a kind"],
  [/^aws$/, (a) => (a[0] === "s3" && (a[1] === "rb" || (a[1] === "rm" && a.includes("--recursive")))) || a.some((w) => /^(?:delete-db-instance|delete-db-cluster|delete-bucket|delete-stack|delete-table|delete-cluster|delete-volume|delete-snapshot|delete-db-snapshot|delete-file-system|delete-repository|delete-function|delete-user|terminate-instances|delete-vpc|delete-hosted-zone|delete-secret|schedule-key-deletion)$/.test(w)), "cloud-delete", "deletes cloud resources (data, volumes, databases or accounts)"],
  [/^gcloud$|^gsutil$/, (a) => a.includes("delete") || (a[0] === "rm" && (a.includes("-r") || a.includes("-R"))) || a[0] === "rb", "cloud-delete", "deletes cloud resources"],
  [/^az$/, (a) => a.includes("delete") || a.includes("purge"), "cloud-delete", "deletes cloud resources"],
  [/^(?:heroku|fly|flyctl|railway|vercel|netlify|render|doctl|linode-cli|hcloud|supabase|neonctl|pscale|turso)$/, (a) => a.some((w) => /^(?:destroy|delete|remove|rm|apps:destroy|addons:destroy|pg:reset)$/.test(w)), "cloud-delete", "deletes a hosted app, database or volume"],
  [/^docker$|^podman$/, (a) => (a[0] === "system" && a[1] === "prune" && (a.includes("--volumes") || a.includes("-a"))) || (a[0] === "volume" && (a[1] === "rm" || a[1] === "prune")), "docker-volume-delete", "deletes container volumes (data)"],
];

function matchTable(table, b, args) {
  for (const [re, pred, rule, reason] of table) {
    if (re.test(b) && pred(args)) return { rule, reason };
  }
  return null;
}

// Classify one simple command (already split). depth guards recursion.
function classifySimple(segment, ctx, depth) {
  const argv0 = words(segment);
  if (argv0.length === 0) return null;
  const { argv, inner } = unwrap(argv0);
  let best = null;
  if (inner && depth < MAX_DEPTH) best = stricter(best, classifyCommandLine(inner, ctx, depth + 1));
  if (argv.length === 0) return best;
  const b = base(argv[0]);
  const args = argv.slice(1);
  const text = segment;

  // The guard's own files and the settings that load it.
  if (writesTo(GUARD_PROTECTED, b, args, text)) {
    best = stricter(best, D("block", "destructive", "guard-self-protection", "changes the Intentrax guard's own files (hook runtime, record, keys, guard rules), the pack policy or the MCP pins; make that change yourself, outside the agent"));
  }
  if (writesTo(CLAUDE_SETTINGS, b, args, text)) {
    best = stricter(best, D("ask", "access", "claude-settings-change", "changes the Claude Code settings or .mcp.json that wire in the Intentrax guard (and your permission rules or MCP servers)"));
  }
  if (/\bguard\b/.test(text) && /\buninstall\b/.test(text) && /intentrax/i.test(text)) {
    best = stricter(best, D("block", "destructive", "guard-self-protection", "uninstalls the Intentrax guard; run `guard uninstall` yourself, outside the agent"));
  }

  // Deleting or moving the folders that hold the guard (.intentrax, .claude).
  if (/^(?:rm|rmdir|mv|move|del|rd|erase|remove-item|ri|move-item|mi|rename-item|unlink|trash|git)$/.test(b)) {
    const targets = args.filter((a) => !a.startsWith("-")).map((a) => a.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, ""));
    const gitOk = b !== "git" || ["rm", "mv"].includes(args[0]);
    if (gitOk && targets.some((t) => /(?:^|\/)\.intentrax$/i.test(t))) {
      best = stricter(best, D("block", "destructive", "guard-self-protection", "deletes or moves the folder that holds the Intentrax guard; do that yourself, outside the agent"));
    }
    if (gitOk && targets.some((t) => /(?:^|\/)\.claude$/i.test(t))) {
      best = stricter(best, D("ask", "access", "claude-settings-change", "deletes or moves the folder that holds the Claude Code settings that load the Intentrax guard"));
    }
  }

  if (/^mkfs(?:\.|$)|^mke2fs$|^newfs/.test(b)) best = stricter(best, D("block", "destructive", "disk-wipe", "formats a disk"));
  if (b === "find" && args.some((a) => a === "-delete" || ((a === "-exec" || a === "-execdir") && /^(?:rm|shred|unlink)$/.test(base(args[args.indexOf(a) + 1] ?? ""))))) {
    best = stricter(best, D("ask", "destructive", "find-delete", "deletes every file that find matches"));
  }

  switch (b) {
    case "rm":
    case "rmdir":
    case "unlink":
    case "del":
    case "rd":
    case "erase": {
      const f = rmFlags(args);
      const recursive = f.recursive || (["rd", "rmdir"].includes(b) && args.some((a) => /^\/s$/i.test(a))) || (b === "del" && args.some((a) => /^\/s$/i.test(a)));
      if (f.noPreserveRoot) {
        best = stricter(best, D("block", "destructive", "rm-root", "recursive delete with --no-preserve-root"));
      } else if (recursive && f.targets.some((t) => CATASTROPHIC_RM_TARGETS.test(t))) {
        best = stricter(best, D("block", "destructive", "rm-root", "recursive delete of a root, home or whole working directory"));
      } else if (recursive) {
        best = stricter(best, D("ask", "destructive", "rm-recursive", "deletes files recursively"));
      }
      break;
    }
    case "remove-item":
    case "ri": {
      const recursive = args.some((a) => /^-r(?:ecurse)?$/i.test(a));
      const targets = args.filter((a) => !a.startsWith("-"));
      if (recursive && targets.some((t) => CATASTROPHIC_RM_TARGETS.test(t) || /^(?:\$env:USERPROFILE|\$HOME|~)[\\/]?\*?$/i.test(t))) {
        best = stricter(best, D("block", "destructive", "rm-root", "recursive delete of a root, home or whole working directory"));
      } else if (recursive) {
        best = stricter(best, D("ask", "destructive", "rm-recursive", "deletes files recursively"));
      }
      break;
    }
    case "wipefs":
    case "shred":
    case "diskpart":
    case "format-volume":
    case "clear-disk":
    case "initialize-disk":
      best = stricter(best, D("block", "destructive", "disk-wipe", "formats or wipes a disk"));
      break;
    case "format":
      if (args.some((a) => /^[A-Za-z]:$/.test(a))) best = stricter(best, D("block", "destructive", "disk-wipe", "formats a drive"));
      break;
    case "dd":
      if (args.some((a) => /^of=\/dev\//.test(a))) best = stricter(best, D("block", "destructive", "disk-wipe", "writes raw bytes to a device"));
      break;
    case "chmod":
    case "chown":
    case "chgrp":
      if ((shortFlag(args, "R") || hasFlag(args, "--recursive")) && args.some((a) => /^(?:\/|~|\$HOME|\/\*)$/.test(a))) {
        best = stricter(best, D("block", "destructive", "chmod-root", "recursively changes permissions or ownership of / or home"));
      }
      break;
    case "shutdown":
    case "reboot":
    case "halt":
    case "poweroff":
    case "stop-computer":
    case "restart-computer":
      best = stricter(best, D("ask", "infrastructure", "power", "shuts down or reboots the machine"));
      break;
    case "git":
      best = stricter(best, classifyGit(args));
      break;
    case "curl":
    case "wget":
    case "invoke-webrequest":
    case "iwr":
    case "invoke-restmethod":
    case "irm": {
      const method = args.find((a, i) => ["-X", "--request", "-Method"].includes(args[i - 1]));
      const writes = (method && !/^(?:GET|HEAD|OPTIONS)$/i.test(method)) || args.some((a) => /^(?:-d|--data(?:-\w+)?|-F|--form|-T|--upload-file|-Body)$/i.test(a));
      if (writes && args.some((a) => /api\.stripe\.com|api\.paypal\.com|squareup\.com|api\.adyen\.com|plaid\.com/i.test(a))) {
        best = stricter(best, D("ask", "financial", "payment-api", "calls a payment API with a write request"));
      } else if (writes && args.some((a) => /api\.sendgrid\.com|api\.mailgun\.net|api\.postmarkapp\.com|api\.resend\.com|hooks\.slack\.com|slack\.com\/api\/chat|api\.twilio\.com|discord(?:app)?\.com\/api\/webhooks/i.test(a))) {
        best = stricter(best, D("ask", "communication", "send-message-api", "sends a message through an email, chat or SMS API"));
      }
      break;
    }
    default:
      break;
  }

  const destroy = matchTable(INFRA_DESTROY, b, args);
  if (destroy) {
    // Whole-environment teardown is always blocked; deleting one cloud resource
    // or a container volume asks, unless the command names production.
    const always = destroy.rule === "iac-destroy" || destroy.rule === "kubectl-delete-wide";
    best = stricter(best, D(always || PROD_HINT.test(text) ? "block" : "ask", "infrastructure", destroy.rule, destroy.reason));
  }
  const publish = matchTable(PUBLISH, b, args);
  if (publish) best = stricter(best, D("ask", publish.rule === "payment" ? "financial" : publish.rule === "send-email" ? "communication" : "deploy", publish.rule, publish.reason));

  if (DB_CLIENTS.has(b) || /\b(?:psql|mysql|sqlite3|mongosh|redis-cli)\b/.test(text)) {
    // Read SQL from the shell-unquoted arguments, one at a time, so shell
    // quoting is never confused with SQL quoting and two -c statements are
    // judged separately.
    const prodHint = PROD_HINT.test(text) || PROD_HINT.test(ctx.envText ?? "");
    for (const sqlText of sqlCandidates(args)) {
      const sql = classifySqlText(sqlText, { prodHint });
      if (sql) best = stricter(best, sql);
    }
    if (b === "redis-cli" && /\bFLUSH(?:ALL|DB)\b/i.test(text)) best = stricter(best, D("block", "database", "sql-drop-truncate", "flushes a Redis database"));
    if (b === "prisma" && /migrate\s+reset|db\s+push.*--force-reset|--accept-data-loss/.test(text)) best = stricter(best, D("block", "database", "db-reset", "resets the database (drops all data)"));
  }
  if (/\b(?:rails|rake)\b.*\bdb:(?:drop|reset|schema:load)\b|\bmanage\.py\s+(?:flush|reset_db)\b|\bknex\s+migrate:rollback\s+--all\b|\bsequelize\s+db:drop\b|\bdrizzle-kit\s+drop\b/.test(text)) {
    best = stricter(best, D("block", "database", "db-reset", "drops or resets a database"));
  }
  return best;
}

// The command line with each heredoc body cut at its closing delimiter line,
// so commands after the heredoc are not read as part of its SQL.
// Every heredoc body, read the way bash reads them: line by line. A command
// line may carry several `<<` markers; their bodies follow it in order, each
// ending at a line that is exactly its delimiter (leading tabs allowed only
// for `<<-`). Lines inside a body are never scanned for markers. A body
// without its delimiter runs to the end of the text.
const HEREDOC_MARKER = /(?<!<)<<(?!<)(-?)[ \t]*\\?(['"]?)([^\s'"<>|;&()]+)\2/g;

export function heredocBodies(text) {
  const bodies = [];
  const pending = []; // { delim, tabs }
  let body = null;
  for (const line of String(text).split("\n")) {
    if (pending.length > 0) {
      const { delim, tabs } = pending[0];
      const candidate = tabs ? line.replace(/^\t+/, "") : line;
      if (candidate === delim) {
        bodies.push((body ?? []).join("\n"));
        body = null;
        pending.shift();
      } else {
        (body ??= []).push(line);
      }
      continue;
    }
    for (const m of line.matchAll(HEREDOC_MARKER)) pending.push({ delim: m[3], tabs: m[1] === "-" });
  }
  if (pending.length > 0) bodies.push((body ?? []).join("\n"));
  return bodies;
}

const SQL_CLIENTS = new Set(["psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo", "redis-cli", "cqlsh", "clickhouse-client", "snowsql", "cockroach", "bq"]);
const SQL_CLIENT_NAME = new RegExp(String.raw`\b(?:` + [...SQL_CLIENTS].map((c) => c.replace(/-/g, "\\-")).join("|") + String.raw`)\b`);

// A segment that runs a database client (directly, or under sudo, env,
// docker exec, kubectl exec, ...), as opposed to one that merely mentions a
// client name as an argument to a read-only command (`grep psql`).
function runsSqlClient(segment) {
  const argv = unwrap(words(segment)).argv;
  if (argv.length === 0) return false;
  const b0 = base(argv[0]);
  if (SQL_CLIENTS.has(b0)) return true;
  // docker / podman / kubectl / oc exec|run ... <client>, ssh host <client>
  if (["docker", "podman", "kubectl", "oc", "nerdctl"].includes(b0) && (argv.includes("exec") || argv.includes("run"))) {
    return argv.slice(1).some((x) => SQL_CLIENTS.has(base(x)) || words(x).some((y) => SQL_CLIENTS.has(base(y))));
  }
  if (b0 === "ssh") return argv.slice(1).some((x) => words(x).some((y) => SQL_CLIENTS.has(base(y))));
  return false;
}

// The line split into pipelines (on ; && || & and newlines, outside quotes),
// each keeping its single `|` pipes.
export function splitPipelines(text) {
  const out = [];
  let cur = "";
  let quote = null;
  let depth = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quote) {
      if (c === "\\" && quote === '"' && i + 1 < text.length) {
        cur += c + text[i + 1];
        i += 1;
        continue;
      }
      if (c === quote) quote = null;
      cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if (c === "\\" && i + 1 < text.length) {
      cur += c + text[i + 1];
      i += 1;
      continue;
    }
    // { …; } and ( … ) groups (and $( … )) stay inside one pipeline:
    // `{ echo '…'; } | psql`.
    if (c === "{" || c === "(") depth += 1;
    else if ((c === "}" || c === ")") && depth > 0) depth -= 1;
    const two = text.slice(i, i + 2);
    if (depth === 0 && (two === "&&" || two === "||")) {
      out.push(cur);
      cur = "";
      i += 1;
      continue;
    }
    if (depth === 0 && (c === ";" || c === "\n" || (c === "&" && text[i - 1] !== ">" && text[i - 1] !== "|" && text[i + 1] !== ">"))) {
      out.push(cur);
      cur = "";
      continue;
    }
    cur += c;
  }
  out.push(cur);
  return out.map((p) => p.trim()).filter(Boolean);
}

// Remote script piped into a shell: `curl ... | sh`. Needs the whole line.
function pipeToShell(line) {
  return /\b(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:iex|invoke-expression)\b/i.test(line);
}

// classifyCommandLine(line) -> { verdict, category, rule, reason } | null
// null means no objection (the call is left to Claude Code's own rules).
export function classifyCommandLine(line, ctx = {}, depth = 0) {
  const text = String(line ?? "");
  if (text.length > 100_000) return D("ask", "unknown", "command-too-long", "command line too long to classify");
  let best = null;
  if (pipeToShell(text)) best = stricter(best, D("ask", "shell", "remote-script", "downloads a script and runs it in a shell"));
  // SQL fed to a database client on stdin: a heredoc (`psql <<EOF … EOF`), a
  // here-string (`psql <<< '…'`) or a pipe (`echo '…' | psql`). The SQL lands
  // in another line or segment, so read it from the line as a whole: the
  // heredoc body up to its closing delimiter, and every shell word of every
  // segment.
  // SQL a database client reads on stdin. (A here-string, `psql <<< '…'`, is
  // an argument of the client command and is read with its arguments.)
  //   heredocs: each body is read as one text, on its own (the shell splitter
  //     cuts a body into per-line "commands", which would separate a
  //     statement from its WHERE);
  //   pipes: the shell words of the other commands in the same pipeline as
  //     the client (`echo '…' | sudo -u postgres psql`), never commands
  //     after && or ;.
  {
    const prodHint = PROD_HINT.test(text);
    const texts = [];
    // Heredoc bodies whenever a client name appears anywhere on the line: the
    // client may get the body indirectly (`ssh db psql <<SQL`, `docker run -i
    // … psql`, `sh -c "psql"`).
    const bodies = SQL_CLIENT_NAME.test(text) ? heredocBodies(text) : [];
    texts.push(...bodies);
    const lineSegments = splitCommandLine(text);
    if (lineSegments.segments.some(runsSqlClient)) {
      const bodyText = bodies.join("\n");
      // Pipes: the other commands of the client's own pipeline.
      for (const pipeline of splitPipelines(text)) {
        if (bodyText && bodyText.includes(pipeline)) continue; // a line inside a heredoc body
        const parts = splitCommandLine(pipeline).segments;
        if (parts.length < 2 || !parts.some(runsSqlClient)) continue;
        for (const part of parts) if (!runsSqlClient(part)) texts.push(...sqlCandidates(words(part)));
      }
      // Process substitution feeding a client: `psql -f <(echo '…')`.
      // (the splitter drops the `<(` itself from the segment text, so test the line)
      if (/<\(/.test(text)) {
        for (const inner of lineSegments.nested) {
          for (const seg of splitCommandLine(inner).segments) texts.push(...sqlCandidates(words(seg)));
        }
      }
    }
    for (const t of texts) {
      const sql = classifySqlText(t, { prodHint });
      if (sql) best = stricter(best, sql);
    }
  }
  if (/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/.test(text)) best = stricter(best, D("block", "destructive", "fork-bomb", "fork bomb"));
  const envText = (text.match(/(?:^|\s)[A-Za-z_][A-Za-z0-9_]*=\S+/g) ?? []).join(" ");
  const { segments, nested } = splitCommandLine(text);
  let count = 0;
  for (const seg of segments) {
    if ((count += 1) > MAX_SEGMENTS) return stricter(best, D("ask", "unknown", "command-too-complex", "command line too complex to classify"));
    best = stricter(best, classifySimple(seg, { ...ctx, envText: (ctx.envText ?? "") + " " + envText }, depth));
  }
  if (depth < MAX_DEPTH) {
    for (const n of nested) best = stricter(best, classifyCommandLine(n, ctx, depth + 1));
  }
  return best;
}
