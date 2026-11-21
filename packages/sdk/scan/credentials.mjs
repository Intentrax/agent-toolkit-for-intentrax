// Credential references and breadth heuristics. The scan records a credential
// only by its variable or config name and where it was found. Values are never
// stored, compared against output, or printed: when a config holds a literal
// value, we record `inline: true` and nothing else.

// Names that look like credentials (env vars, config keys, headers, flags).
export const CREDENTIAL_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIALS?|AUTH(?!OR)|(^|[_-])PAT$|^PAT$|DSN$|DATABASE[_-]?URL|DB[_-]?URL|CONNECTION[_-]?STRING|KUBECONFIG|SERVICE[_-]?ROLE|[_-]KEY$|^KEY$|COOKIE)/i;

export function isCredentialName(name) {
  return CREDENTIAL_NAME.test(String(name ?? ""));
}

// `${VAR}`, `${env:VAR}`, `$VAR`, `%VAR%`, `{env:VAR}`: returns the referenced
// variable names. A value with no reference is treated as an inline literal.
export function referencedVars(value) {
  const out = [];
  const re = /\$\{(?:env:|input:)?([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%|\{env:([A-Za-z_][A-Za-z0-9_]*)\}/g;
  let m;
  while ((m = re.exec(String(value ?? "")))) out.push(m[1] ?? m[2] ?? m[3] ?? m[4]);
  return out;
}

const PLATFORMS = [
  ["github", /GITHUB|(^|_)GH_/],
  ["gitlab", /GITLAB/],
  ["stripe", /STRIPE/],
  ["aws", /(^|_)AWS(_|$)/],
  ["gcp", /GOOGLE|(^|_)GCP(_|$)|GCLOUD/],
  ["azure", /AZURE/],
  ["cloudflare", /CLOUDFLARE|(^|_)CF_/],
  ["supabase", /SUPABASE/],
  ["kubernetes", /KUBE/],
  ["slack", /SLACK/],
  ["database", /DATABASE|POSTGRES|(^|_)PG|MYSQL|MONGO|(^|_)DB(_|$)|REDIS/],
];

export function platformOf(name) {
  const upper = String(name).toUpperCase();
  for (const [p, re] of PLATFORMS) if (re.test(upper)) return p;
  return "generic";
}

const SCOPED_ALTERNATIVE = {
  github: "a fine-grained personal access token or GitHub App installation token limited to the repositories and permissions this agent needs",
  gitlab: "a project access token limited to one project and the scopes this agent needs",
  stripe: "a restricted key with only the resource permissions this agent needs",
  aws: "an IAM role whose policy allows only the actions and resources this agent needs, with no delete actions unless one tool truly needs them",
  gcp: "a service account with a narrow predefined or custom role on only the resources this agent needs",
  azure: "a managed identity or service principal with a narrow role assignment on one resource group",
  cloudflare: "an API token scoped to the zones and permissions this agent needs (not the global API key)",
  supabase: "the anon key with row-level security, or a database role limited to the tables and statements this agent needs",
  kubernetes: "a service account bound to a namespaced Role with only the verbs this agent needs",
  slack: "a bot token with only the scopes this agent needs",
  database: "a database role limited to the tables and statements this agent needs (and a separate read-only role for reads)",
  generic: "a token limited to the project, resources and actions this agent needs, with no delete or admin rights",
};

export function scopedAlternative(name) {
  return SCOPED_ALTERNATIVE[platformOf(name)];
}

// Breadth rules, most specific first. `label` is the phrase used in the finding
// line ("reachable with an account-wide token").
const BREADTH_RULES = [
  { re: /ACCOUNT[_-]?(API[_-]?)?(TOKEN|KEY|SECRET)|ACCOUNT[_-]?WIDE/, label: "an account-wide token", why: 'name contains "ACCOUNT" with TOKEN/KEY' },
  { re: /(^|_)(ORG|ORGANI[SZ]ATION)[_-]?(ADMIN[_-]?)?(TOKEN|KEY|SECRET)/, label: "an organization-wide token", why: 'name contains "ORG" with TOKEN/KEY' },
  { re: /GLOBAL[_-]?API[_-]?KEY|^CLOUDFLARE_API_KEY$|^CF_API_KEY$/, label: "an account-wide global API key", why: "global API keys carry every permission of the account" },
  { re: /SERVICE[_-]?ROLE/, label: "a service-role key", why: "service-role keys bypass row-level security" },
  { re: /FULL[_-]?ACCESS|ALL[_-]?ACCESS|UNRESTRICTED|GOD[_-]?MODE/, label: "a full-access token", why: 'name says "full/all access"' },
  { re: /(^|_)(SUPERUSER|SUPER_USER|SUDO)(_|$)/, label: "a superuser credential", why: 'name contains "SUPERUSER"/"SUDO"' },
  { re: /(^|_)ROOT(_|$)/, label: "a root credential", why: 'name contains "ROOT"' },
  { re: /(^|_)(ADMIN|ADMINISTRATOR)(_|$)/, label: "an admin token", why: 'name contains "ADMIN"' },
  { re: /(^|_)OWNER(_|$)/, label: "an owner token", why: 'name contains "OWNER"' },
  { re: /(^|_)MASTER(_|$)/, label: "a master key", why: 'name contains "MASTER"' },
  { re: /^(GITHUB_PERSONAL_ACCESS_TOKEN|GITHUB_PAT|GH_PAT|GITLAB_PERSONAL_ACCESS_TOKEN)$/, label: "a personal access token", why: "a personal access token acts as the user; a classic token with repo scope reaches every repository the user can" },
  { re: /^STRIPE_(SECRET_KEY|API_KEY|SECRET|KEY)$/, label: "a full-access secret key", why: "a standard Stripe secret key has full API access (restricted keys exist)" },
  { re: /^AWS_(SECRET_ACCESS_KEY|ACCESS_KEY_ID|SECRET_KEY)$/, label: "a long-lived cloud access key", why: "long-lived IAM access keys are often attached to broad policies; their scope is not visible in the repository" },
  { re: /^(GOOGLE_APPLICATION_CREDENTIALS|GCP_SERVICE_ACCOUNT_KEY|GCLOUD_SERVICE_KEY|GOOGLE_CREDENTIALS)$/, label: "a service-account key", why: "service-account key files are often granted project-wide roles; their scope is not visible in the repository" },
  { re: /^AZURE_CLIENT_SECRET$/, label: "a service-principal secret", why: "service-principal role assignments are often subscription-wide; their scope is not visible in the repository" },
  { re: /^(DIGITALOCEAN_(ACCESS_)?TOKEN|DO_TOKEN|HEROKU_API_KEY|VERCEL_TOKEN|NETLIFY_AUTH_TOKEN|FLY_API_TOKEN|LINODE_TOKEN|HCLOUD_TOKEN|RENDER_API_KEY|RAILWAY_API_TOKEN)$/, label: "a platform API token", why: "this platform's API tokens are account- or team-wide unless created with a narrower scope" },
  { re: /KUBECONFIG/, label: "cluster credentials", why: "kubeconfig credentials are often cluster-admin" },
];

const GITHUB_TOKEN_NAMES = /^(GITHUB_TOKEN|GH_TOKEN)$/;
const REPO_WIDE_SCOPE_HINT = /scopes?\W{0,40}["'](?:repo|admin:org|delete_repo|workflow|admin:repo_hook)["']|["'](?:delete_repo|admin:org)["']/i;

// Returns null when the name gives no breadth signal. `contextText` is the
// file the credential was referenced from, used only for GitHub scope hints.
export function credentialBreadth(name, contextText = "") {
  const upper = String(name ?? "").toUpperCase();
  for (const rule of BREADTH_RULES) {
    if (rule.re.test(upper)) return { label: rule.label, heuristic: true, reason: rule.why };
  }
  if (GITHUB_TOKEN_NAMES.test(upper) && REPO_WIDE_SCOPE_HINT.test(contextText)) {
    return { label: "a repo-wide GitHub token", heuristic: true, reason: "the same file mentions repo-wide scopes (repo, admin:org, delete_repo or workflow)" };
  }
  return null;
}

// Env reads in source code: process.env.X, os.environ["X"], os.getenv("X") ...
const ENV_READ = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*["']([^"']+)["']\s*\]|os\.environ\[\s*["']([^"']+)["']\s*\]|os\.environ\.get\(\s*["']([^"']+)["']|os\.getenv\(\s*["']([^"']+)["']|Deno\.env\.get\(\s*["']([^"']+)["']|Bun\.env\.([A-Za-z_][A-Za-z0-9_]*)|import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)/g;
const ENV_DESTRUCTURE = /\{([^{}]{1,400})\}\s*=\s*(?:process\.env|Bun\.env|import\.meta\.env)\b/g;

export function envReadsIn(text, from = 0, to = text.length) {
  const slice = text.slice(from, to);
  const out = [];
  let m;
  ENV_READ.lastIndex = 0;
  while ((m = ENV_READ.exec(slice))) {
    const name = m.slice(1).find((g) => g !== undefined);
    if (name) out.push({ name, index: from + m.index });
  }
  ENV_DESTRUCTURE.lastIndex = 0;
  while ((m = ENV_DESTRUCTURE.exec(slice))) {
    for (const part of m[1].split(",")) {
      const name = part.split(/[:=]/)[0].trim();
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) out.push({ name, index: from + m.index });
    }
  }
  return out.filter((r) => isCredentialName(r.name));
}
