// Read-back recipe: one database row, through a query function you pass.
//
// Minimum scope: a database role with SELECT on the tables the query reads
// and nothing else (for example Postgres `GRANT SELECT ON orders TO readback;`
// on a role with no INSERT/UPDATE/DELETE), ideally on a read replica, with
// `default_transaction_read_only = on` for that role.
//
//   const check = sqlRow({
//     query: (sql, params) => readonlyPool.query(sql, params),   // pg: returns { rows }
//     sql: "SELECT status, amount_cents FROM refunds WHERE id = $1",
//     params: ["rf_2291"],
//     resource: "refund rf_2291",
//   });
//
// `query(sql, params, { signal })` may return an array of rows or an object
// with a `rows` array (node-postgres, mysql2's [rows] is NOT accepted: pass
// `(sql, p) => pool.query(sql, p).then(([rows]) => rows)`). Exactly one row
// must match; zero rows is an error (UNKNOWN) unless you pass `notFoundAs`,
// and more than one row is always an error.
//
// The SQL text is checked lexically: it must be a single SELECT (or WITH …
// SELECT) statement without data-modifying keywords or row locks. That check
// is a tripwire for mistakes, NOT a security boundary — the read-only role is
// what actually keeps the check from writing.

import { checkNotFoundAs, defineRecipe, requireString } from "./_shared.mjs";

// Keywords that cannot appear in a plain read. (Postgres allows INSERT /
// UPDATE / DELETE / MERGE inside WITH; SELECT … INTO creates a table; FOR
// UPDATE takes locks.) Functions with side effects (nextval, pg_notify, your
// own) cannot be caught lexically: the read-only role is the real guard.
const WRITE_KEYWORDS = /\b(insert|update|delete|merge|upsert|truncate|drop|alter|create|grant|revoke|copy|call|exec|execute|lock|into|set|nextval|setval|pg_notify|dblink_exec)\b/i;

function stripLiteralsAndComments(sql) {
  return sql
    .replace(/--[^\n]*/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/'(?:[^']|'')*'/g, "''")
    .replace(/"(?:[^"]|"")*"/g, '""')
    .replace(/`[^`]*`/g, "``");
}

/** Throws TypeError unless `sql` looks like one read-only SELECT statement. */
export function assertReadOnlySql(sql) {
  requireString("sql", sql, { max: 20000 });
  const bare = stripLiteralsAndComments(sql).trim().replace(/;\s*$/, "");
  if (bare.includes(";")) throw new TypeError("sql must be a single statement");
  if (!/^(select|with)\b/i.test(bare)) throw new TypeError("sql must start with SELECT or WITH");
  const hit = bare.match(WRITE_KEYWORDS);
  if (hit) throw new TypeError("sql contains a non-read keyword: " + hit[1].toUpperCase());
  if (/\bfor\s+(no\s+key\s+)?(share|key\s+share)\b/i.test(bare)) throw new TypeError("sql must not take row locks");
  return sql;
}

/**
 * @param {object} opts
 * @param {(sql: string, params: unknown[], ctx: { signal?: AbortSignal }) => Promise<unknown>} opts.query
 * @param {string} opts.sql
 * @param {unknown[]} [opts.params]
 * @param {string} [opts.resource]
 * @param {string} [opts.source]       default "database"
 * @param {object} [opts.notFoundAs]   observation when no row matches
 * @param {Record<string,unknown[]>} [opts.pending]
 */
export function sqlRow(opts = {}) {
  const { query, sql, params = [], resource, source = "database", notFoundAs, pending } = opts;
  if (typeof query !== "function") throw new TypeError("query must be a function (sql, params) => rows");
  assertReadOnlySql(sql);
  if (!Array.isArray(params)) throw new TypeError("params must be an array");
  checkNotFoundAs(notFoundAs);

  return defineRecipe({
    href: import.meta.url,
    exportName: "sqlRow",
    options: opts, // holds a function, so this check always runs in-process
    secrets: [],
    resource: resource || "row",
    source,
    pending,
    read: async ({ signal }) => {
      const result = await query(sql, params.slice(), { signal });
      const rows = Array.isArray(result) ? result : result && Array.isArray(result.rows) ? result.rows : null;
      if (rows === null) throw new Error("query returned neither an array of rows nor { rows: [...] }");
      if (rows.length === 0) {
        if (notFoundAs !== undefined) return structuredClone(notFoundAs);
        throw new Error("no row matched");
      }
      if (rows.length > 1) throw new Error("query matched " + rows.length + " rows; expected exactly one");
      const row = rows[0];
      if (row === null || typeof row !== "object" || Array.isArray(row)) throw new Error("row is not an object of columns");
      const out = {};
      for (const [k, v] of Object.entries(row)) if (v !== undefined) out[k] = v;
      return out;
    },
  });
}
