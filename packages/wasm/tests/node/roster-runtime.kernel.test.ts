import { describe, expect, it } from 'vitest';

import {
    actionSignatureKeyGenerationRandomnessByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';
import {
    completionRosterByteLength,
    openRosterRuntime,
} from '../../src/roster-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
const participantCount = 10;

const pseudorandomBytes = (length: number, seed: bigint): Uint8Array => {
    let state = seed;
    const mask = (1n << 64n) - 1n;
    return Uint8Array.from({ length }, () => {
        state ^= (state << 13n) & mask;
        state ^= state >> 7n;
        state ^= (state << 17n) & mask;
        state &= mask;
        return Number(state & 0xffn);
    });
};

describe('completion roster scalar WASM runtime', () => {
    it('binds one signing and one mailbox credential per fixed position', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const signatureRuntime = openActionSignatureRuntime(kernel);
        const mailboxRuntime = openPairEncryptionRuntime(kernel);
        const rosterRuntime = openRosterRuntime(kernel);
        const signingKeyPairs = Array.from(
            { length: participantCount },
            (_, position) =>
                signatureRuntime.generateKeyPair(
                    pseudorandomBytes(
                        actionSignatureKeyGenerationRandomnessByteLength,
                        0x1000n + BigInt(position),
                    ),
                ),
        );
        const mailboxKeyPairs = Array.from(
            { length: participantCount },
            (_, position) =>
                mailboxRuntime.generateKeyPair(
                    pseudorandomBytes(
                        pairEncryptionKeyGenerationRandomnessByteLength,
                        0x2000n + BigInt(position),
                    ),
                ),
        );
        const publicKeys = signingKeyPairs.map((signing, position) => ({
            signingVerificationKey: signing.verificationKey,
            mailboxEncapsulationKey:
                mailboxKeyPairs[position]?.encryptionKey ?? new Uint8Array(),
        }));
        const roster = rosterRuntime.encode(publicKeys);

        expect(roster.canonicalBytes).toHaveLength(completionRosterByteLength);
        expect(rosterRuntime.verify(roster.canonicalBytes)).toEqual(
            roster.rosterIdentity,
        );
        expect(
            rosterRuntime.verifyCredentials(
                roster.canonicalBytes,
                7,
                signingKeyPairs[7]?.secretKey ?? new Uint8Array(),
                mailboxKeyPairs[7]?.decryptionKey ?? new Uint8Array(),
            ),
        ).toEqual(roster.rosterIdentity);
        expect(
            rosterRuntime.resolveMailboxKey(
                roster.rosterIdentity,
                2,
                7,
                roster.canonicalBytes,
            ),
        ).toEqual(mailboxKeyPairs[7]?.encryptionKey);

        expect(() =>
            rosterRuntime.verifyCredentials(
                roster.canonicalBytes,
                7,
                signingKeyPairs[6]?.secretKey ?? new Uint8Array(),
                mailboxKeyPairs[7]?.decryptionKey ?? new Uint8Array(),
            ),
        ).toThrowError(ConstructionKernelCommandError);
        const malformedMailboxKey = Uint8Array.from(
            publicKeys[0]?.mailboxEncapsulationKey ?? new Uint8Array(),
        );
        malformedMailboxKey.subarray(0, 3).fill(0xff);
        expect(() =>
            rosterRuntime.encode(
                publicKeys.map((keys, position) =>
                    position === 0
                        ? {
                              ...keys,
                              mailboxEncapsulationKey: malformedMailboxKey,
                          }
                        : keys,
                ),
            ),
        ).toThrowError(ConstructionKernelCommandError);
        const mutatedRoster = Uint8Array.from(roster.canonicalBytes);
        mutatedRoster[mutatedRoster.byteLength - 1] ^= 1;
        expect(rosterRuntime.verify(mutatedRoster)).not.toEqual(
            roster.rosterIdentity,
        );
        expect(() =>
            rosterRuntime.resolveMailboxKey(
                roster.rosterIdentity,
                2,
                7,
                mutatedRoster,
            ),
        ).toThrowError(ConstructionKernelCommandError);
    });
});
