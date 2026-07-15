/** Hex hash string used for canonical protocol objects and policies. */
export type ProtocolHash = string;

const protocolHashPattern = /^[0-9a-f]{128}$/u;

export const isProtocolHash = (value: unknown): value is ProtocolHash =>
    typeof value === 'string' && protocolHashPattern.test(value);
