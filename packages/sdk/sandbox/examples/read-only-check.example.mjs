// Example read-only check for `intentrax sandbox --check`.
//
// Copy this file, point it at YOUR system, and run it AFTER your agent's
// action has run:
//
//   intentrax sandbox --check ./my-check.mjs
//
// Contract:
//   - `expected` (required): the fields your action should have set, and the
//     values it should have set them to. Plain JSON, integers only. This is
//     what the local decision authorises, and what the read is compared with.
//   - `resource` (optional): a label for the thing being checked.
//   - default export: an async function that READS the current state and
//     returns an object containing at least the fields in `expected`. Only
//     those fields are compared (the coverage boundary).
//
// Read-only by contract: the sandbox calls this function once and never
// calls your write path. It cannot stop this function from writing, so keep
// it to reads. Because you wrote it, the sandbox labels the read
// SELF_REPORTED, not an Intentrax-pulled authoritative read.

export const resource = "ticket:EXAMPLE-1";

export const expected = { status: "closed", assignee: "agent:triage" };

export default async function check({ resource: _resource, fields: _fields }) {
  // Replace with a real read of your system, for example:
  //   const res = await fetch(`https://your-api.example/tickets/1`, { headers: { authorization: `Bearer ${readOnlyToken}` } });
  //   const ticket = await res.json();
  //   return { status: ticket.status, assignee: ticket.assignee };
  return { status: "closed", assignee: "agent:triage" };
}
