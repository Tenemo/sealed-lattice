import {
    deriveProtocolDigest,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    BallotPackageShell,
    BallotPackageWitness,
    ProtocolDigest,
    ProtocolSignatureEnvelope,
    PvssBallotAlgebraInput,
    PvssBallotRosterEntry,
    RefusalRecord,
    ThresholdProfile,
} from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';

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
    'ballotPackageDigest' | 'signature'
>;

export const deriveBallotPackageDigest = (
    ballotPackage: BallotPackageShellPayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotPackageDigest', {
        ballotPolynomialSetDigest: ballotPackage.ballotPolynomialSetDigest,
        ceremonyId: ballotPackage.ceremonyId,
        duplicateBallotPolicyDigest: ballotPackage.duplicateBallotPolicyDigest,
        electionManifestDigest: ballotPackage.electionManifestDigest,
        objectType: ballotPackage.objectType,
        objectVersion: ballotPackage.objectVersion,
        optionCount: ballotPackage.optionCount,
        pollSpecDigest: ballotPackage.pollSpecDigest,
        receiverPayloadDigests: ballotPackage.receiverPayloadDigests,
        receiverShareCommitments: ballotPackage.receiverShareCommitments,
        rosterDigest: ballotPackage.rosterDigest,
        shareVectorWidth: ballotPackage.shareVectorWidth,
        thresholdProfileDigest: ballotPackage.thresholdProfileDigest,
        voterIdentity: ballotPackage.voterIdentity,
        voterRosterPosition: ballotPackage.voterRosterPosition,
    });

export const deriveTestBallotPackage = (
    input: PvssBallotAlgebraInput,
    createSignature: (
        ballotPackageDigest: ProtocolDigest,
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
            ballotPolynomialSetDigest: polynomialSet.ballotPolynomialSetDigest,
        }),
    );
    const receiverShareCommitments = commitmentPayloads.map(({ witness }) => ({
        trusteeIdentity: witness.commitment.trusteeIdentity,
        trusteeRosterPosition: witness.commitment.trusteeRosterPosition,
        shareCommitmentDigest: witness.commitment.shareCommitmentDigest,
    }));
    const receiverPayloadDigests = commitmentPayloads.map(({ payload }) => ({
        receiverIdentity: payload.receiverIdentity,
        receiverRosterPosition: payload.receiverRosterPosition,
        payloadDigest: payload.payloadDigest,
    }));
    const unsignedBallotPackage = {
        objectType: 'BallotPackage' as const,
        objectVersion: 1 as const,
        ceremonyId: input.ceremonyId,
        electionManifestDigest: input.electionManifestDigest,
        rosterDigest: input.rosterDigest,
        pollSpecDigest: input.pollSpecDigest,
        thresholdProfileDigest: input.thresholdProfileDigest,
        duplicateBallotPolicyDigest: input.duplicateBallotPolicyDigest,
        voterIdentity: input.voterIdentity,
        voterRosterPosition: input.voterRosterPosition,
        optionCount: input.pollSpec.options.length,
        shareVectorWidth: pvssBallotShareVectorWidth,
        ballotPolynomialSetDigest: polynomialSet.ballotPolynomialSetDigest,
        receiverShareCommitments,
        receiverPayloadDigests,
    };
    const ballotPackageDigest = deriveBallotPackageDigest(
        unsignedBallotPackage,
    );
    const signature = createSignature(
        ballotPackageDigest,
        unsignedBallotPackage,
    );

    return {
        ballotPackage: {
            ...unsignedBallotPackage,
            ballotPackageDigest,
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
        input.ballotPackage.receiverPayloadDigests.length !==
            input.thresholdProfile.rosterSize
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package must include one commitment and payload digest for every roster receiver.',
                input.ballotPackage.ballotPackageDigest,
                'BallotPackage',
            ),
        );
    }

    rosterEntries.forEach((entry, entryIndex) => {
        const commitment =
            input.ballotPackage.receiverShareCommitments[entryIndex];
        const payload = input.ballotPackage.receiverPayloadDigests[entryIndex];

        if (
            commitment?.trusteeIdentity !== entry.participantIdentity ||
            commitment.trusteeRosterPosition !== entry.rosterPosition
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot package receiver commitments must match the frozen roster order.',
                    input.ballotPackage.ballotPackageDigest,
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
                    'Ballot package receiver payload digests must match the frozen roster order.',
                    input.ballotPackage.ballotPackageDigest,
                    'BallotPackage',
                ),
            );
        }
        if (commitment !== undefined) {
            const commitmentKey = [
                commitment.trusteeIdentity,
                commitment.trusteeRosterPosition,
            ].join('\u0000');
            if (commitmentKeys.has(commitmentKey)) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot package receiver commitments must be unique.',
                        input.ballotPackage.ballotPackageDigest,
                        'BallotPackage',
                    ),
                );
            }
            commitmentKeys.add(commitmentKey);
        }
        if (payload !== undefined) {
            const payloadKey = [
                payload.receiverIdentity,
                payload.receiverRosterPosition,
            ].join('\u0000');
            if (payloadKeys.has(payloadKey)) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot package receiver payload digests must be unique.',
                        input.ballotPackage.ballotPackageDigest,
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
    readonly electionManifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly optionCount: number;
    readonly rosterEntries: readonly PvssBallotRosterEntry[];
    readonly thresholdProfile: ThresholdProfile;
}): readonly RefusalRecord[] => {
    const { ballotPackage } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveBallotPackageDigest({
        objectType: ballotPackage.objectType,
        objectVersion: ballotPackage.objectVersion,
        ceremonyId: ballotPackage.ceremonyId,
        electionManifestDigest: ballotPackage.electionManifestDigest,
        rosterDigest: ballotPackage.rosterDigest,
        pollSpecDigest: ballotPackage.pollSpecDigest,
        thresholdProfileDigest: ballotPackage.thresholdProfileDigest,
        duplicateBallotPolicyDigest: ballotPackage.duplicateBallotPolicyDigest,
        voterIdentity: ballotPackage.voterIdentity,
        voterRosterPosition: ballotPackage.voterRosterPosition,
        optionCount: ballotPackage.optionCount,
        shareVectorWidth: ballotPackage.shareVectorWidth,
        ballotPolynomialSetDigest: ballotPackage.ballotPolynomialSetDigest,
        receiverShareCommitments: ballotPackage.receiverShareCommitments,
        receiverPayloadDigests: ballotPackage.receiverPayloadDigests,
    });

    if (ballotPackage.ballotPackageDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package digest does not match its canonical payload.',
                ballotPackage.ballotPackageDigest,
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
                ballotPackage.ballotPackageDigest,
                'BallotPackage',
            ),
        );
    }
    if (
        ballotPackage.ceremonyId !== input.ceremonyId ||
        ballotPackage.electionManifestDigest !== input.electionManifestDigest ||
        ballotPackage.rosterDigest !== input.rosterDigest ||
        ballotPackage.pollSpecDigest !== input.pollSpecDigest ||
        ballotPackage.thresholdProfileDigest !== input.thresholdProfileDigest ||
        ballotPackage.duplicateBallotPolicyDigest !==
            input.duplicateBallotPolicyDigest ||
        ballotPackage.optionCount !== input.optionCount
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot package context does not match the frozen election context.',
                ballotPackage.ballotPackageDigest,
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
                ballotPackage.ballotPackageDigest,
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

    if (voterRosterEntry?.signingPublicKeyDigest !== undefined) {
        const signatureResult = verifySignedObjectSignature(
            ballotPackage.signature,
            {
                objectType: 'BallotPackage',
                objectVersion: 1,
                signerRole: 'Voter',
                signerIdentity: ballotPackage.voterIdentity,
                ceremonyId: ballotPackage.ceremonyId,
                publicKeyDigest: voterRosterEntry.signingPublicKeyDigest,
                manifestDigest: ballotPackage.electionManifestDigest,
                objectRoot: ballotPackage.ballotPackageDigest,
                boardHeadDigest: null,
            },
        );

        refusedObjects.push(...signatureResult.refusedObjects);
    }

    return refusedObjects;
};
