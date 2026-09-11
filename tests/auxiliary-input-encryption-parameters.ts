import { verifyProthCertificate } from '#tests/fixed-modulus-bfv-model.js';

export const auxiliaryInputEncryptionParameters = {
    degree: 4096n,
    plaintextModulus: 257n,
    modulus: verifyProthCertificate(257n * 101n, 20, 3n),
    scale: 101n * (1n << 20n),
    support: 256n,
} as const;
