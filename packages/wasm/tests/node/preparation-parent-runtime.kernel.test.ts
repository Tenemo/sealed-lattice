import { describe, expect, it } from 'vitest';

import {
    actionSignatureKeyGenerationRandomnessByteLength,
    actionSignatureSigningRandomnessByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
    pairEncryptionRandomnessByteLength,
    type PairEncryptionKeyPair,
} from '../../src/pair-encryption-runtime.js';
import {
    actionSignatureCarrierByteLength,
    openPreparationParentRuntime,
    preparationParentBodyByteLength,
} from '../../src/preparation-parent-runtime.js';
import {
    openPrivatePreparationBodyRuntime,
    privatePreparationBodyByteLength,
    privatePreparationPlaintextByteLength,
    type PrivatePreparationContextInput,
} from '../../src/private-preparation-body-runtime.js';
import { openRosterRuntime } from '../../src/roster-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
const participantCount = 10;
const senderPosition = 2;
const recipientPosition = 8;

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

describe('preparation parent scalar WASM runtime', () => {
    it('verifies the exact signed manifest before admitting a private carrier', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const signatureRuntime = openActionSignatureRuntime(kernel);
        const pairRuntime = openPairEncryptionRuntime(kernel);
        const rosterRuntime = openRosterRuntime(kernel);
        const bodyRuntime = openPrivatePreparationBodyRuntime(kernel);
        const parentRuntime = openPreparationParentRuntime(kernel);
        const actionProposalIdentity = pseudorandomBytes(64, 0x4a31n);
        const rosterPublicKeys: Array<{
            signingVerificationKey: Uint8Array;
            mailboxEncapsulationKey: Uint8Array;
        }> = [];
        let senderPreparationSecretKey: Uint8Array | undefined;
        let incomingPair: PairEncryptionKeyPair | undefined;

        for (
            let rosterPosition = 0;
            rosterPosition < participantCount;
            rosterPosition += 1
        ) {
            const signatureKeyPair = signatureRuntime.generateKeyPair(
                pseudorandomBytes(
                    actionSignatureKeyGenerationRandomnessByteLength,
                    0x1000n + BigInt(rosterPosition),
                ),
            );
            const mailboxKeyPair = pairRuntime.generateKeyPair(
                pseudorandomBytes(
                    pairEncryptionKeyGenerationRandomnessByteLength,
                    0x9000n + BigInt(rosterPosition),
                ),
            );
            if (rosterPosition === senderPosition) {
                senderPreparationSecretKey = signatureKeyPair.secretKey;
            }
            if (rosterPosition === recipientPosition) {
                incomingPair = mailboxKeyPair;
            }
            rosterPublicKeys.push({
                signingVerificationKey: signatureKeyPair.verificationKey,
                mailboxEncapsulationKey: mailboxKeyPair.encryptionKey,
            });
        }

        const roster = rosterRuntime.encode(rosterPublicKeys);
        const canonicalRosterBytes = roster.canonicalBytes;
        const rosterIdentity = roster.rosterIdentity;
        expect(senderPreparationSecretKey).toBeDefined();
        expect(incomingPair).toBeDefined();
        if (
            senderPreparationSecretKey === undefined ||
            incomingPair === undefined
        ) {
            throw new Error('test key custody was not constructed');
        }

        const context: PrivatePreparationContextInput = {
            participantCount,
            actionProposalIdentity,
            rosterIdentity,
            preparationAttempt: 7,
            predecessorIdentity: pseudorandomBytes(64, 0x3311n),
            senderPosition,
            recipientPosition,
        };
        const privateCarrier = bodyRuntime.seal(
            context,
            incomingPair.encryptionKey,
            pseudorandomBytes(pairEncryptionRandomnessByteLength, 0x8123n),
            pseudorandomBytes(privatePreparationPlaintextByteLength, 0x77b1n),
        );
        expect(privateCarrier.body).toHaveLength(
            privatePreparationBodyByteLength,
        );

        const privateBodyIdentities: Uint8Array[] = [];
        for (
            let candidateRecipient = 0;
            candidateRecipient < participantCount;
            candidateRecipient += 1
        ) {
            if (candidateRecipient === senderPosition) {
                continue;
            }
            privateBodyIdentities.push(
                candidateRecipient === recipientPosition
                    ? privateCarrier.identity
                    : pseudorandomBytes(
                          64,
                          0xb000n + BigInt(candidateRecipient),
                      ),
            );
        }
        const parent = parentRuntime.encode({
            participantCount,
            actionProposalIdentity,
            rosterIdentity,
            preparationAttempt: context.preparationAttempt,
            predecessorIdentity: context.predecessorIdentity,
            senderPosition,
            subsetCommitments: pseudorandomBytes(120 * 64, 0xc011n),
            privateBodyIdentities,
        });
        expect(parent.body).toHaveLength(
            preparationParentBodyByteLength(participantCount),
        );
        const parentSignature = signatureRuntime.signBodyIdentity(
            senderPreparationSecretKey,
            senderPosition,
            'preparation',
            parent.identity,
            pseudorandomBytes(
                actionSignatureSigningRandomnessByteLength,
                0x4711n,
            ),
        );
        const signatureCarrier = parentRuntime.encodeSignature(
            participantCount,
            senderPosition,
            parent.identity,
            parentSignature,
        );
        expect(signatureCarrier).toHaveLength(actionSignatureCarrierByteLength);
        expect(signatureCarrier.slice(0, 4)).toEqual(
            Uint8Array.of(0x05, 0x02, 0x04, 0x00),
        );

        expect(
            parentRuntime.verifyPrivateCarrier(
                context,
                canonicalRosterBytes,
                parent.body,
                signatureCarrier,
                privateCarrier.body,
            ),
        ).toEqual({
            senderPosition,
            recipientPosition,
            parentIdentity: parent.identity,
            bodyIdentity: privateCarrier.identity,
        });

        const mutatedSignature = Uint8Array.from(signatureCarrier);
        mutatedSignature[mutatedSignature.byteLength - 1] ^= 1;
        expect(() =>
            parentRuntime.verifyPrivateCarrier(
                context,
                canonicalRosterBytes,
                parent.body,
                mutatedSignature,
                privateCarrier.body,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const withdrawnSchemaSignature = Uint8Array.from(signatureCarrier);
        withdrawnSchemaSignature[2] = 3;
        expect(() =>
            parentRuntime.verifyPrivateCarrier(
                context,
                canonicalRosterBytes,
                parent.body,
                withdrawnSchemaSignature,
                privateCarrier.body,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const mutatedBody = Uint8Array.from(privateCarrier.body);
        mutatedBody[mutatedBody.byteLength - 1] ^= 1;
        expect(() =>
            parentRuntime.verifyPrivateCarrier(
                context,
                canonicalRosterBytes,
                parent.body,
                signatureCarrier,
                mutatedBody,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const reorderedRoster = Uint8Array.from(canonicalRosterBytes);
        reorderedRoster[reorderedRoster.byteLength - 1] ^= 1;
        expect(() =>
            parentRuntime.verifyPrivateCarrier(
                context,
                reorderedRoster,
                parent.body,
                signatureCarrier,
                privateCarrier.body,
            ),
        ).toThrow(ConstructionKernelCommandError);
    });
});
