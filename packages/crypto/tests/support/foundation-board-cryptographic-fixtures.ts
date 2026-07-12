import { shake256 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const textEncoder = new TextEncoder();
const objectSignatureContext = textEncoder.encode(
    'sealed-lattice/object-signature/v1',
);

export type FoundationBoardSigningKeyPairFixture = Readonly<{
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}>;

export const createFoundationBoardSigningKeyPairFixtures = (
    participantCount: number,
): readonly FoundationBoardSigningKeyPairFixture[] =>
    Array.from({ length: participantCount }, (_, rosterPosition) => {
        const seed = new Uint8Array(32);
        seed[0] = rosterPosition + 1;
        seed[31] = participantCount - rosterPosition;
        try {
            return ml_dsa65.keygen(seed);
        } finally {
            seed.fill(0);
        }
    });

export const hashFoundationBoardFixtureFrame = (
    canonicalHashFrame: Uint8Array,
): Uint8Array => {
    const hash = shake256.create({ dkLen: 64 });
    hash.update(canonicalHashFrame);
    return hash.digest();
};

export const signFoundationBoardFixtureMessage = (
    message: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array =>
    ml_dsa65.sign(message, secretKey, {
        context: objectSignatureContext,
        extraEntropy: false,
    });
