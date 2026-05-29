import {
    deriveProtocolHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    BallotPackageShell,
    BallotPackageWitness,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    PvssBallotAlgebraInput,
    PvssBallotRosterEntry,
    RefusalRecord,
    ThresholdProfile,
} from '@sealed-lattice/types';

import {
    createRefusal,
    defaultSignedRootContextHash,
    isProtocolHashString,
    signedObjectRootByteLength,
} from '../common/verification-helpers.js';

import { deriveBallotPolynomialSet } from './ballot-polynomials.js';
import {
    getRosterEntryByIdentity,
    pvssBallotShareVectorWidth,
    requireNoRefusals,
    sortRosterEntries,
    validatePollAndThreshold,
    validateRosterEntries,
} from './common.js';
import { deriveReceiverShareVectors } from './receiver-shares.js';
import { deriveTestShareCommitmentWitness } from './test-share-commitments.js';

type BallotPackageShellPayload = Omit<
    BallotPackageShell,
    'ballotPackageHash' | 'signature'
>;

const deriveBallotPackageHash = (
    ballotPackage: BallotPackageShellPayload,
): ProtocolHash =>
    deriveProtocolHash('BallotPackageHash', {
        ballotPolynomialSetHash: ballotPackage.ballotPolynomialSetHash,
        ceremonyId: ballotPackage.ceremonyId,
        duplicateBallotPolicyHash: ballotPackage.duplicateBallotPolicyHash,
        electionManifestHash: ballotPackage.electionManifestHash,
        objectType: ballotPackage.objectType,
        objectVersion: ballotPackage.objectVersion,
        optionCount: ballotPackage.optionCount,
        pollSpecHash: ballotPackage.pollSpecHash,
        receiverPayloadHashes: ballotPackage.receiverPayloadHashes,
        receiverShareCommitments: ballotPackage.receiverShareCommitments,
        rosterHash: ballotPackage.rosterHash,
        shareVectorWidth: ballotPackage.shareVectorWidth,
        thresholdProfileHash: ballotPackage.thresholdProfileHash,
        voterIdentity: ballotPackage.voterIdentity,
        voterRosterPosition: ballotPackage.voterRosterPosition,
    });

export const deriveTestBallotPackage = (
    input: PvssBallotAlgebraInput,
    createSignature: (
        ballotPackageHash: ProtocolHash,
        unsignedBallotPackage: BallotPackageShellPayload,
    ) => ProtocolSignatureEnvelope,
): BallotPackageWitness => {
    requireNoRefusals([
        ...validatePollAndThreshold(input.pollSpec, input.thresholdProfile),
        ...validateRosterEntries(input.rosterEntries, input.thresholdProfile),
    ]);

    const polynomialSet = deriveBallotPolynomialSet(input);
    const receiverShareVectors = deriveReceiverShareVectors({
        polynomialSet,
        rosterEntries: input.rosterEntries,
        thresholdProfile: input.thresholdProfile,
    });
    const commitmentPayloads = receiverShareVectors.map((receiverShareVector) =>
        deriveTestShareCommitmentWitness({
            context: input,
            receiverShareVector,
            ballotPolynomialSetHash: polynomialSet.ballotPolynomialSetHash,
        }),
    );
    const receiverShareCommitments = commitmentPayloads.map(({ witness }) => ({
        receiverIdentity: witness.commitment.receiverIdentity,
        receiverRosterPosition: witness.commitment.receiverRosterPosition,
        shareCommitmentHash: witness.commitment.shareCommitmentHash,
    }));
    const receiverPayloadHashes = commitmentPayloads.map(({ payload }) => ({
        receiverIdentity: payload.receiverIdentity,
        receiverRosterPosition: payload.receiverRosterPosition,
        payloadHash: payload.payloadHash,
    }));
    const unsignedBallotPackage = {
        objectType: 'BallotPackage' as const,
        objectVersion: 1 as const,
        ceremonyId: input.ceremonyId,
        electionManifestHash: input.electionManifestHash,
        rosterHash: input.rosterHash,
        pollSpecHash: input.pollSpecHash,
        thresholdProfileHash: input.thresholdProfileHash,
        duplicateBallotPolicyHash: input.duplicateBallotPolicyHash,
        voterIdentity: input.voterIdentity,
        voterRosterPosition: input.voterRosterPosition,
        optionCount: input.pollSpec.options.length,
        shareVectorWidth: pvssBallotShareVectorWidth,
        ballotPolynomialSetHash: polynomialSet.ballotPolynomialSetHash,
        receiverShareCommitments,
        receiverPayloadHashes,
    };
    const ballotPackageHash = deriveBallotPackageHash(unsignedBallotPackage);
    const signature = createSignature(ballotPackageHash, unsignedBallotPackage);

    return {
        ballotPackage: {
            ...unsignedBallotPackage,
            ballotPackageHash,
            signature,
        },
        polynomialSet,
        receiverShareVectors,
        shareCommitmentWitnesses: commitmentPayloads.map(
            ({ witness }) => witness,
        ),
        receiverPayloads: commitmentPayloads.map(({ payload }) => payload),
    };
};

const collectReceiverReferenceRefusals = (input: {
    readonly ballotPackage: BallotPackageShell;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const rosterEntries = sortRosterEntries(input.rosterEntries);
    const commitmentKeys = new Set<string>();
    const payloadKeys = new Set<string>();

    if (
        input.ballotPackage.receiverShareCommitments.length !==
            input.thresholdProfile.rosterSize ||
        input.ballotPackage.receiverPayloadHashes.length !==
            input.thresholdProfile.rosterSize
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package must include one commitment and payload hash for every roster receiver.',
                input.ballotPackage.ballotPackageHash,
                'BallotPackage',
            ),
        );
    }

    rosterEntries.forEach((entry, entryIndex) => {
        const commitment =
            input.ballotPackage.receiverShareCommitments[entryIndex];
        const payload = input.ballotPackage.receiverPayloadHashes[entryIndex];

        if (
            commitment?.receiverIdentity !== entry.participantIdentity ||
            commitment.receiverRosterPosition !== entry.rosterPosition
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot package receiver commitments must match the frozen roster order.',
                    input.ballotPackage.ballotPackageHash,
                    'BallotPackage',
                ),
            );
        }
        if (
            payload?.receiverIdentity !== entry.participantIdentity ||
            payload.receiverRosterPosition !== entry.rosterPosition
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot package receiver payload Hashes must match the frozen roster order.',
                    input.ballotPackage.ballotPackageHash,
                    'BallotPackage',
                ),
            );
        }
        if (commitment !== undefined) {
            if (!isProtocolHashString(commitment.shareCommitmentHash)) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot package receiver commitments must bind canonical hash references.',
                        input.ballotPackage.ballotPackageHash,
                        'BallotPackage',
                    ),
                );
            }
            const commitmentKey = [
                commitment.receiverIdentity,
                commitment.receiverRosterPosition,
            ].join('\u0000');
            if (commitmentKeys.has(commitmentKey)) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot package receiver commitments must be unique.',
                        input.ballotPackage.ballotPackageHash,
                        'BallotPackage',
                    ),
                );
            }
            commitmentKeys.add(commitmentKey);
        }
        if (payload !== undefined) {
            if (!isProtocolHashString(payload.payloadHash)) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot package receiver payloads must bind canonical hash references.',
                        input.ballotPackage.ballotPackageHash,
                        'BallotPackage',
                    ),
                );
            }
            const payloadKey = [
                payload.receiverIdentity,
                payload.receiverRosterPosition,
            ].join('\u0000');
            if (payloadKeys.has(payloadKey)) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot package receiver payload Hashes must be unique.',
                        input.ballotPackage.ballotPackageHash,
                        'BallotPackage',
                    ),
                );
            }
            payloadKeys.add(payloadKey);
        }
    });

    return refusedObjects;
};

export const verifyBallotPackageShell = (input: {
    readonly ballotPackage: BallotPackageShell;
    readonly ceremonyId: string;
    readonly electionManifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly thresholdProfileHash: ProtocolHash;
    readonly duplicateBallotPolicyHash: ProtocolHash;
    readonly optionCount: number;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): readonly RefusalRecord[] => {
    const { ballotPackage } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveBallotPackageHash({
        objectType: ballotPackage.objectType,
        objectVersion: ballotPackage.objectVersion,
        ceremonyId: ballotPackage.ceremonyId,
        electionManifestHash: ballotPackage.electionManifestHash,
        rosterHash: ballotPackage.rosterHash,
        pollSpecHash: ballotPackage.pollSpecHash,
        thresholdProfileHash: ballotPackage.thresholdProfileHash,
        duplicateBallotPolicyHash: ballotPackage.duplicateBallotPolicyHash,
        voterIdentity: ballotPackage.voterIdentity,
        voterRosterPosition: ballotPackage.voterRosterPosition,
        optionCount: ballotPackage.optionCount,
        shareVectorWidth: ballotPackage.shareVectorWidth,
        ballotPolynomialSetHash: ballotPackage.ballotPolynomialSetHash,
        receiverShareCommitments: ballotPackage.receiverShareCommitments,
        receiverPayloadHashes: ballotPackage.receiverPayloadHashes,
    });

    if (ballotPackage.ballotPackageHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package hash does not match its canonical payload.',
                ballotPackage.ballotPackageHash,
                'BallotPackage',
            ),
        );
    }
    if (
        ballotPackage.objectType !== 'BallotPackage' ||
        ballotPackage.objectVersion !== 1 ||
        ballotPackage.shareVectorWidth !== pvssBallotShareVectorWidth
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package object shape is not canonical.',
                ballotPackage.ballotPackageHash,
                'BallotPackage',
            ),
        );
    }
    if (
        ballotPackage.ceremonyId !== input.ceremonyId ||
        ballotPackage.electionManifestHash !== input.electionManifestHash ||
        ballotPackage.rosterHash !== input.rosterHash ||
        ballotPackage.pollSpecHash !== input.pollSpecHash ||
        ballotPackage.thresholdProfileHash !== input.thresholdProfileHash ||
        ballotPackage.duplicateBallotPolicyHash !==
            input.duplicateBallotPolicyHash ||
        ballotPackage.optionCount !== input.optionCount
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package context does not match the frozen election context.',
                ballotPackage.ballotPackageHash,
                'BallotPackage',
            ),
        );
    }

    const voterRosterEntry = getRosterEntryByIdentity(
        input.rosterEntries,
        ballotPackage.voterIdentity,
    );
    if (
        voterRosterEntry?.rosterPosition !== ballotPackage.voterRosterPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package voter must match a frozen roster entry.',
                ballotPackage.ballotPackageHash,
                'BallotPackage',
            ),
        );
    }

    refusedObjects.push(
        ...validateRosterEntries(input.rosterEntries, input.thresholdProfile),
        ...collectReceiverReferenceRefusals({
            ballotPackage,
            rosterEntries: input.rosterEntries,
            thresholdProfile: input.thresholdProfile,
        }),
    );

    if (
        voterRosterEntry !== undefined &&
        voterRosterEntry.signingPublicKeyHash === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package voter signature cannot be verified without a frozen roster signing key.',
                ballotPackage.ballotPackageHash,
                'BallotPackage',
            ),
        );
    } else if (voterRosterEntry?.signingPublicKeyHash !== undefined) {
        const signatureResult = verifySignedObjectSignature(
            ballotPackage.signature,
            {
                objectType: 'BallotPackage',
                objectVersion: 1,
                signerRole: 'Voter',
                signerIdentity: ballotPackage.voterIdentity,
                ceremonyId: ballotPackage.ceremonyId,
                publicKeyHash: voterRosterEntry.signingPublicKeyHash,
                manifestHash: ballotPackage.electionManifestHash,
                objectRoot: ballotPackage.ballotPackageHash,
                boardHeadHash: null,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: 0,
                deviceEpoch: 0,
                contextHash: defaultSignedRootContextHash,
            },
        );

        refusedObjects.push(...signatureResult.refusedObjects);
    }

    return refusedObjects;
};
