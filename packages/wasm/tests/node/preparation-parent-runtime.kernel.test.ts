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

const expectConstructionErrorCode = (
    operation: () => unknown,
    code: ConstructionKernelCommandError['code'],
): void => {
    try {
        operation();
        throw new Error('The construction operation unexpectedly succeeded.');
    } catch (error: unknown) {
        expect(error).toBeInstanceOf(ConstructionKernelCommandError);
        expect(error).toMatchObject({ code });
    }
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
        expectConstructionErrorCode(
            () =>
                parentRuntime.verifyPrivateCarrier(
                    context,
                    canonicalRosterBytes,
                    parent.body,
                    signatureCarrier,
                    mutatedBody,
                ),
            'InvalidProtocolObject',
        );

        const wrongContextParent = parentRuntime.encode({
            participantCount,
            actionProposalIdentity: pseudorandomBytes(64, 0x4a32n),
            rosterIdentity,
            preparationAttempt: context.preparationAttempt,
            predecessorIdentity: context.predecessorIdentity,
            senderPosition,
            subsetCommitments: pseudorandomBytes(120 * 64, 0xc012n),
            privateBodyIdentities,
        });
        const wrongContextSignature = parentRuntime.encodeSignature(
            participantCount,
            senderPosition,
            wrongContextParent.identity,
            signatureRuntime.signBodyIdentity(
                senderPreparationSecretKey,
                senderPosition,
                'preparation',
                wrongContextParent.identity,
                pseudorandomBytes(
                    actionSignatureSigningRandomnessByteLength,
                    0x4712n,
                ),
            ),
        );
        expectConstructionErrorCode(
            () =>
                parentRuntime.verifyPrivateCarrier(
                    context,
                    canonicalRosterBytes,
                    wrongContextParent.body,
                    wrongContextSignature,
                    privateCarrier.body,
                ),
            'InvalidProtocolObject',
        );

        const falseSenderParent = parentRuntime.encode({
            participantCount,
            actionProposalIdentity,
            rosterIdentity,
            preparationAttempt: context.preparationAttempt,
            predecessorIdentity: context.predecessorIdentity,
            senderPosition: senderPosition + 1,
            subsetCommitments: pseudorandomBytes(120 * 64, 0xc013n),
            privateBodyIdentities,
        });
        const falseSenderSignature = parentRuntime.encodeSignature(
            participantCount,
            senderPosition,
            falseSenderParent.identity,
            signatureRuntime.signBodyIdentity(
                senderPreparationSecretKey,
                senderPosition,
                'preparation',
                falseSenderParent.identity,
                pseudorandomBytes(
                    actionSignatureSigningRandomnessByteLength,
                    0x4713n,
                ),
            ),
        );
        expectConstructionErrorCode(
            () =>
                parentRuntime.verifyPrivateCarrier(
                    context,
                    canonicalRosterBytes,
                    falseSenderParent.body,
                    falseSenderSignature,
                    privateCarrier.body,
                ),
            'AttributableProtocolViolation',
        );

        const wrongMailboxPair = pairRuntime.generateKeyPair(
            pseudorandomBytes(
                pairEncryptionKeyGenerationRandomnessByteLength,
                0x9011n,
            ),
        );
        const wrongMailboxCarrier = bodyRuntime.seal(
            context,
            wrongMailboxPair.encryptionKey,
            pseudorandomBytes(pairEncryptionRandomnessByteLength, 0x8124n),
            pseudorandomBytes(privatePreparationPlaintextByteLength, 0x77b2n),
        );
        const privateBodyIndex =
            recipientPosition < senderPosition
                ? recipientPosition
                : recipientPosition - 1;
        const wrongMailboxBodyIdentities = privateBodyIdentities.map(
            (identity, index) =>
                index === privateBodyIndex
                    ? wrongMailboxCarrier.identity
                    : identity,
        );
        const wrongMailboxParent = parentRuntime.encode({
            participantCount,
            actionProposalIdentity,
            rosterIdentity,
            preparationAttempt: context.preparationAttempt,
            predecessorIdentity: context.predecessorIdentity,
            senderPosition,
            subsetCommitments: pseudorandomBytes(120 * 64, 0xc014n),
            privateBodyIdentities: wrongMailboxBodyIdentities,
        });
        const wrongMailboxSignature = parentRuntime.encodeSignature(
            participantCount,
            senderPosition,
            wrongMailboxParent.identity,
            signatureRuntime.signBodyIdentity(
                senderPreparationSecretKey,
                senderPosition,
                'preparation',
                wrongMailboxParent.identity,
                pseudorandomBytes(
                    actionSignatureSigningRandomnessByteLength,
                    0x4714n,
                ),
            ),
        );
        expectConstructionErrorCode(
            () =>
                parentRuntime.verifyPrivateCarrier(
                    context,
                    canonicalRosterBytes,
                    wrongMailboxParent.body,
                    wrongMailboxSignature,
                    wrongMailboxCarrier.body,
                ),
            'AttributableProtocolViolation',
        );

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
