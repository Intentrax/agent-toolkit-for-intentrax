// Types for canonical.mjs: RFC 8785 canonical JSON and domain-separated SHA-256.

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

/** RFC 8785 canonical JSON. Throws on NaN, Infinity, undefined members, non-plain objects, bigint. */
export function canonicalJson(value: JsonValue): string;

/** Lower-case hex SHA-256 of a string or bytes. */
export function sha256Hex(data: string | Uint8Array): string;

/** "sha256:" + hex(SHA-256(domain || canonicalJson(value))). */
export function domainDigest(domain: string, value: JsonValue): `sha256:${string}`;
