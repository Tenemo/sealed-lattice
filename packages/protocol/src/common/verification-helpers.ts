export const protocolHashPattern = /^[0-9a-f]{128}$/u;

export const isProtocolHashString = (value: unknown): value is string =>
    typeof value === 'string' && protocolHashPattern.test(value);

export const isRecord = (
    value: unknown,
): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null;
