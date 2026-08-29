export const wasm32UsizeByteLength = 4;

export const sha256HexPattern = /^[a-f0-9]{64}$/u;

export const textDecoder = new TextDecoder('utf-8', { fatal: true });

export const textEncoder = new TextEncoder();

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
