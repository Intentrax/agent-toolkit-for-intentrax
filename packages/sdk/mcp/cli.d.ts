/** `intentrax mcp pin|check|proxy`. Resolves to the exit code (0 match, 10 drift, 2 unchecked, 1 usage). */
export function mcpMain(
  argv?: string[],
  io?: {
    out?: (text: string) => unknown;
    err?: (text: string) => unknown;
    cwd?: string;
    env?: Record<string, string | undefined>;
    invokedAs?: string;
    input?: NodeJS.ReadableStream;
    output?: NodeJS.WritableStream;
    errorOutput?: { write(chunk: string | Uint8Array): unknown };
  },
): Promise<number>;
export function parseMcpArgs(argv: string[]): { sub: "pin" | "check" | "proxy" | "help"; opts: Record<string, unknown> };
export function usage(invokedAs?: string): string;
