// A 512-bit digest has 128 base-16 digits and a three-digit checksum.
// The twelve signing purposes use a sixteen-leaf tree and a four-node path.
export const purposeSignatureSizes = {
    publicKeyBytes: 64n,
    signatureBytes: 2n + (128n + 3n + 4n) * 64n,
} as const;
