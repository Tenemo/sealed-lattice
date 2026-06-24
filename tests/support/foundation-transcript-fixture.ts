import {
    canonicalJson,
    deriveProtocolHash,
    hash512Hex,
} from '#packages/crypto/src/index';
import {
    deriveRosterExternalAcceptanceHash,
    deriveRosterHash,
} from '#packages/protocol/src/roster/hashes';
import {
    ceremonyId,
    createBoardEvidence,
    createBoardHeadWithObjects,
    createRegistrationEntry,
    createRosterManifestTranscriptInput,
    createSignature,
    createTargetFinalityRecord,
    deriveFixtureHash,
    manifestOpaqueBindings,
    manifestPolicyHashes,
    targetFinalityPolicy,
    witnessPolicy,
    witnessPublicKeyHashes,
} from '#packages/protocol/tests/node/election-foundation-test-helpers';
import type {
    FoundationTranscriptInput,
    GoldenTranscriptCoreFixture,
    ProtocolHash,
    RegistrationEntry,
    RosterExternalAcceptance,
    RosterExternalAcceptanceVerificationInput,
    TargetFinalityVerificationInput,
    ValidatedFirstValidObject,
} from '#packages/types/src/index';

export const foundationParticipantCount = 10;
export const foundationOptionCount = 20;
export const foundationTopOptionCount = 10;
export const foundationTiePolicyHash = deriveFixtureHash(
    'fixture-tie-policy-v1',
    { tiePolicy: 'HigherScoreThenLowerOptionIndex' },
);

export type FoundationTranscriptFixture = {
    readonly input: FoundationTranscriptInput;
    readonly expectedHashes: FoundationTranscriptExpectedHashes;
    readonly targetFinality: TargetFinalityVerificationInput;
};

export type FoundationTranscriptExpectedHashes = {
    readonly electionManifestHash: ProtocolHash;
    readonly firstValidOrderHash: ProtocolHash;
    readonly rosterExternalAcceptanceHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly targetFinalityCheckpointHash: ProtocolHash;
    readonly targetFinalityRecordHash: ProtocolHash;
    readonly targetProposalHash: ProtocolHash;
    readonly thresholdParametersHash: ProtocolHash;
};

const textEncoder = new TextEncoder();

const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const hash512Bytes = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array => hexToBytes(hash512Hex(domain, parts));
const transcriptCoreChunkSize = 8;

const bytesToHex = (bytes: Uint8Array): string =>
    [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const appendVarUint = (output: number[], value: number): void => {
    let remainingValue = value;

    do {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        output.push(byte);
    } while (remainingValue !== 0);
};

const appendBytes = (output: number[], value: Uint8Array): void => {
    appendVarUint(output, value.byteLength);
    output.push(...value);
};

const appendString = (output: number[], value: string): void =>
    appendBytes(output, textEncoder.encode(value));

const varUintBytes = (value: number): Uint8Array => {
    const bytes: number[] = [];

    appendVarUint(bytes, value);

    return Uint8Array.from(bytes);
};

const transcriptCoreObjectRoot = (canonicalBytes: Uint8Array): string =>
    hash512Hex('sealed-lattice-root/canonical-root-v1', [
        varUintBytes(1),
        varUintBytes(1),
        canonicalBytes,
    ]);

const transcriptCoreChunkRoot = (
    canonicalBytes: Uint8Array,
    chunkSize: number,
): string => {
    const leaves: Uint8Array[] = [];

    for (
        let chunkStart = 0, chunkIndex = 0;
        chunkStart < canonicalBytes.byteLength;
        chunkStart += chunkSize, chunkIndex += 1
    ) {
        leaves.push(
            hash512Bytes('transcript-core/chunk-leaf', [
                varUintBytes(chunkIndex),
                canonicalBytes.slice(chunkStart, chunkStart + chunkSize),
            ]),
        );
    }

    if (leaves.length === 0) {
        leaves.push(hash512Bytes('transcript-core/chunk-empty', []));
    }

    let currentLevel = leaves;
    while (currentLevel.length > 1) {
        const nextLevel: Uint8Array[] = [];
        for (
            let leafIndex = 0;
            leafIndex < currentLevel.length;
            leafIndex += 2
        ) {
            const left = currentLevel[leafIndex];
            const right = currentLevel[leafIndex + 1] ?? left;
            nextLevel.push(
                hash512Bytes('transcript-core/chunk-node', [left, right]),
            );
        }
        currentLevel = nextLevel;
    }

    return hash512Hex('transcript-core/chunk-root', [
        varUintBytes(chunkSize),
        varUintBytes(canonicalBytes.byteLength),
        currentLevel[0],
    ]);
};

const encodeFoundationTranscriptCoreBytes = (
    payloadBytes: Uint8Array,
): Uint8Array => {
    const bytes: number[] = [];
    const tags = [
        'canonical',
        'foundation-transcript',
        'direct-route',
    ] as const;
    const checkpoints = [
        foundationParticipantCount,
        foundationOptionCount,
        foundationTopOptionCount,
    ] as const;

    bytes.push(...textEncoder.encode('SLBE'));
    appendVarUint(bytes, 1);
    appendVarUint(bytes, 1);
    appendVarUint(bytes, 1);
    appendVarUint(bytes, 5);
    appendVarUint(bytes, 1);
    appendString(bytes, 'Foundation transcript roots');
    appendVarUint(bytes, 2);
    appendVarUint(bytes, 10);
    appendVarUint(bytes, 3);
    appendBytes(bytes, payloadBytes);
    appendVarUint(bytes, 4);
    appendVarUint(bytes, tags.length);
    for (const tag of tags) {
        appendString(bytes, tag);
    }
    appendVarUint(bytes, 5);
    appendVarUint(bytes, checkpoints.length);
    for (const checkpoint of checkpoints) {
        appendVarUint(bytes, checkpoint);
    }

    return Uint8Array.from(bytes);
};

const encodeFoundationTranscriptCorePayload = (
    expectedHashes: FoundationTranscriptExpectedHashes,
): Uint8Array =>
    textEncoder.encode(
        canonicalJson({
            expectedHashes,
            optionCount: foundationOptionCount,
            participantCount: foundationParticipantCount,
            purpose: 'foundation-transcript-root-parity',
            schemaVersion: 1,
            topOptionCount: foundationTopOptionCount,
        }),
    );

export const createFoundationTranscriptCoreFixture = (
    expectedHashes: FoundationTranscriptExpectedHashes,
): GoldenTranscriptCoreFixture => {
    const payloadBytes = encodeFoundationTranscriptCorePayload(expectedHashes);
    const canonicalBytes = encodeFoundationTranscriptCoreBytes(payloadBytes);

    return {
        canonicalBytesHex: bytesToHex(canonicalBytes),
        caseName: 'foundation-transcript-roots',
        chunkSize: transcriptCoreChunkSize,
        expectedChunkRoot: transcriptCoreChunkRoot(
            canonicalBytes,
            transcriptCoreChunkSize,
        ),
        expectedObjectHash512: transcriptCoreObjectRoot(canonicalBytes),
        fixtureVersion: 1,
        kind: 'golden-transcript-core',
        objectType: 'TranscriptCore',
        objectVersion: 1,
    };
};

const createFoundationRegistrations = (): readonly RegistrationEntry[] =>
    Array.from({ length: foundationParticipantCount - 1 }, (_, index) =>
        createRegistrationEntry(`participant-${String(index + 1)}`, 1, index),
    );

const requireRegistration = (
    registrations: readonly RegistrationEntry[],
    participantIdentity: string,
): RegistrationEntry => {
    const registration = registrations.find(
        (entry) => entry.participantIdentity === participantIdentity,
    );

    if (registration === undefined) {
        throw new Error(
            `Missing registration fixture for ${participantIdentity}.`,
        );
    }

    return registration;
};

const createRosterExternalAcceptanceInput = (
    registration: RegistrationEntry,
    rosterHash: ProtocolHash,
    electionManifestHash: ProtocolHash,
    acceptedBoardHeadHash: ProtocolHash,
): RosterExternalAcceptanceVerificationInput => {
    const payload = {
        objectType: 'RosterExternalAcceptance',
        objectVersion: 1,
        ceremonyId,
        participantIdentity: registration.participantIdentity,
        rosterHash,
        electionManifestHash,
        acceptedBoardHeadHash,
        warningTextVersion: 'foundation-warning-text-v1',
    } satisfies Omit<
        RosterExternalAcceptance,
        'rosterExternalAcceptanceHash' | 'signature'
    >;
    const rosterExternalAcceptanceHash =
        deriveRosterExternalAcceptanceHash(payload);
    const acceptance = {
        ...payload,
        rosterExternalAcceptanceHash,
        signature: createSignature(
            'RosterExternalAcceptance',
            'Participant',
            registration.participantIdentity,
            registration.signingPublicKeyHash,
            rosterExternalAcceptanceHash,
            {
                boardHeadHash: acceptedBoardHeadHash,
                manifestHash: electionManifestHash,
            },
        ),
    };

    return {
        acceptance,
        expectedAcceptedBoardHeadHash: acceptedBoardHeadHash,
        expectedCeremonyId: ceremonyId,
        expectedElectionManifestHash: electionManifestHash,
        expectedParticipantPublicKeyHash: registration.signingPublicKeyHash,
        expectedRosterHash: rosterHash,
    };
};

const createFirstValidCandidate = (
    participantIdentity: string,
    boardSequence: number,
    boardPosition: number,
    actionSequence: number,
    contextHash: ProtocolHash,
    isByteIdenticalRetransmission = false,
): ValidatedFirstValidObject => ({
    actionSequence,
    boardPosition,
    boardSequence,
    contextHash,
    deviceEpoch: 0,
    isByteIdenticalRetransmission,
    objectHash: deriveProtocolHash('CiphertextRoot', {
        actionSequence,
        boardPosition,
        boardSequence,
        participantIdentity,
        purpose: 'foundation-encrypted-ballot-shell',
    }),
    objectType: 'EncryptedBallot',
    recoveryEpoch: 0,
    signerIdentity: participantIdentity,
});

export const createFoundationTranscriptFixture =
    (): FoundationTranscriptFixture => {
        const rosterManifestTranscript = createRosterManifestTranscriptInput(
            createFoundationRegistrations(),
        );
        const rosterHash = deriveRosterHash(
            rosterManifestTranscript.registrationEntries,
        );
        const manifestHead =
            rosterManifestTranscript.boardEvidence.signedBoardHeads[
                rosterManifestTranscript.boardEvidence.signedBoardHeads.length -
                    1
            ];

        if (manifestHead === undefined) {
            throw new Error(
                'Foundation fixture requires a manifest board head.',
            );
        }

        const acceptanceRegistration = requireRegistration(
            rosterManifestTranscript.registrationEntries,
            'participant-1',
        );
        const rosterExternalAcceptance = createRosterExternalAcceptanceInput(
            acceptanceRegistration,
            rosterHash,
            rosterManifestTranscript.electionManifest.electionManifestHash,
            manifestHead.headHash,
        );
        const firstValidContextHash = deriveProtocolHash('ActionContextHash', {
            electionManifestHash:
                rosterManifestTranscript.electionManifest.electionManifestHash,
            purpose: 'foundation-first-valid-context',
            rosterExternalAcceptanceHash:
                rosterExternalAcceptance.acceptance
                    .rosterExternalAcceptanceHash,
        });
        const firstValidObjects = [
            createFirstValidCandidate(
                'participant-2',
                4,
                1,
                0,
                firstValidContextHash,
            ),
            createFirstValidCandidate(
                'participant-1',
                4,
                0,
                0,
                firstValidContextHash,
            ),
        ];
        const duplicateFirstValidObject = {
            ...firstValidObjects[1],
            actionSequence: 1,
            boardPosition: 2,
            isByteIdenticalRetransmission: true,
        };
        const currentRecoveryEpochMap = Object.fromEntries(
            rosterManifestTranscript.registrationEntries.map((entry) => [
                entry.participantIdentity,
                {
                    currentDeviceEpoch: entry.deviceEpoch,
                    currentRecoveryEpoch: entry.recoveryEpoch,
                    signerIdentity: entry.participantIdentity,
                },
            ]),
        );
        const evaluatorReplayRecordHash = deriveFixtureHash(
            'fixture-evaluator-replay-record-v1',
            {
                electionManifestHash:
                    rosterManifestTranscript.electionManifest
                        .electionManifestHash,
                proposal: 'foundation-direct-evaluator-replay',
            },
        );
        const { head: targetHead } = createBoardHeadWithObjects(
            manifestHead.boardSequence + 1,
            manifestHead.headHash,
            [
                {
                    boardPosition: 0,
                    objectHash: evaluatorReplayRecordHash,
                    objectType: 'EvaluatorReplayRecord',
                },
            ],
        );
        const targetFinalityRecord = createTargetFinalityRecord(
            targetHead,
            evaluatorReplayRecordHash,
            5,
            {
                electionManifestHash:
                    rosterManifestTranscript.electionManifest
                        .electionManifestHash,
                encryptedBallotAggregateHash: deriveProtocolHash(
                    'CiphertextRoot',
                    {
                        electionManifestHash:
                            rosterManifestTranscript.electionManifest
                                .electionManifestHash,
                        purpose: 'foundation-encrypted-ballot-aggregate',
                    },
                ),
                evaluatorReplayContextHash: deriveProtocolHash(
                    'EvaluatorReplayContextHash',
                    {
                        electionManifestHash:
                            rosterManifestTranscript.electionManifest
                                .electionManifestHash,
                        purpose: 'foundation-evaluator-replay-context',
                    },
                ),
                evaluatorReplayParametersHash:
                    manifestOpaqueBindings.evaluatorReplayParametersHash,
                targetCiphertextHash: deriveProtocolHash('CiphertextRoot', {
                    electionManifestHash:
                        rosterManifestTranscript.electionManifest
                            .electionManifestHash,
                    purpose: 'foundation-target-ciphertext',
                }),
                targetFinalityPolicyHash:
                    manifestPolicyHashes.targetFinalityPolicyHash,
                targetLayoutHash: manifestOpaqueBindings.targetLayoutHash,
                thresholdParametersHash:
                    rosterManifestTranscript.frozenRosterParameters
                        .thresholdParametersHash,
                tiePolicyHash: foundationTiePolicyHash,
                topOptionCount:
                    rosterManifestTranscript.pollSpec.topOptionCount,
            },
        );
        const targetFinality = {
            boardEvidence: createBoardEvidence([
                ...rosterManifestTranscript.boardEvidence.signedBoardHeads,
                targetHead,
            ]),
            record: targetFinalityRecord,
            targetFinalityPolicy,
            witnessPolicy,
            witnessPublicKeyHashes,
        };
        const input: FoundationTranscriptInput = {
            expectedTiePolicyHash: foundationTiePolicyHash,
            expectedTopOptionCount: foundationTopOptionCount,
            firstValidOrdering: {
                currentRecoveryEpochMap,
                expectedSelectionPolicyHash:
                    manifestPolicyHashes.firstValidPolicyHash,
                objects: [...firstValidObjects, duplicateFirstValidObject],
                requiredContextHash: firstValidContextHash,
                selectionPolicyHash: manifestPolicyHashes.firstValidPolicyHash,
            },
            recoveryEpochUpdates: [],
            rosterExternalAcceptance,
            rosterManifestTranscript,
            targetFinality,
        };

        return {
            expectedHashes: {
                electionManifestHash:
                    rosterManifestTranscript.electionManifest
                        .electionManifestHash,
                firstValidOrderHash: deriveProtocolHash('FirstValidOrderHash', {
                    orderedObjectHashes: [
                        firstValidObjects[1].objectHash,
                        firstValidObjects[0].objectHash,
                    ],
                    purpose: 'first-valid-order-v1',
                    requiredContextHash: firstValidContextHash,
                    selectionPolicyHash:
                        manifestPolicyHashes.firstValidPolicyHash,
                }),
                rosterExternalAcceptanceHash:
                    rosterExternalAcceptance.acceptance
                        .rosterExternalAcceptanceHash,
                rosterHash,
                targetFinalityCheckpointHash:
                    targetFinalityRecord.targetFinalityCheckpoint
                        .targetFinalityCheckpointHash,
                targetFinalityRecordHash:
                    targetFinalityRecord.targetFinalityRecordHash,
                targetProposalHash: targetFinalityRecord.targetProposalHash,
                thresholdParametersHash:
                    rosterManifestTranscript.frozenRosterParameters
                        .thresholdParametersHash,
            },
            input,
            targetFinality,
        };
    };
