export const protocolHashPattern = /^[0-9a-f]{128}$/u;

export const isProtocolHashString = (value: unknown): value is string =>
    typeof value === 'string' && protocolHashPattern.test(value);
