import {
    protocolHashNamespaceValues,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    CapabilityContext,
    FirstValidOrderingInput,
    PollSpecInput,
    ProtocolAction,
    ProtocolSignatureEnvelope,
    RecoveryEpochVerificationInput,
    RosterManifestTranscriptInput,
    SignatureVerificationResult,
    StructuredProtocolVerificationResult,
    TargetFinalityVerificationInput,
    ThresholdProfile,
    ThresholdProfileInput,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    deriveValidatedFirstValidOrder,
    deriveThresholdProfile,
    evaluateActionCapability,
    isValidLifecycleTransition,
    validatePollSpec,
    verifyBoardConsistency,
    verifyRecoveryEpochUpdate,
    verifyRosterManifestTranscript,
    verifyTargetFinality,
} from '../../src/index';

import boardFinalityJson from '#test-vectors/election-foundation/board-finality.json';
import capabilityRefusalsJson from '#test-vectors/election-foundation/capability-refusals.json';
import deterministicFixturesJson from '#test-vectors/election-foundation/deterministic-fixtures.json';
import lifecycleTransitionsJson from '#test-vectors/election-foundation/lifecycle-transitions.json';
import pollSpecsJson from '#test-vectors/election-foundation/poll-specs.json';
import thresholdProfilesJson from '#test-vectors/election-foundation/threshold-profiles.json';

type ThresholdProfileVector = {
    readonly caseName: string;
    readonly input: ThresholdProfileInput;
    readonly expected: ThresholdProfile;
};

type ThresholdProfileVectors = {
    readonly schemaVersion: 1;
    readonly profiles: readonly ThresholdProfileVector[];
};

type PollSpecVector = {
    readonly caseName: string;
    readonly input: PollSpecInput;
    readonly expectedOk: boolean;
    readonly expectedErrorCodes?: readonly string[];
};

type PollSpecVectors = {
    readonly schemaVersion: 1;
    readonly cases: readonly PollSpecVector[];
};

type LifecycleTransitionVector = {
    readonly from: CapabilityContext['lifecycleState'];
    readonly to: CapabilityContext['lifecycleState'];
};

type LifecycleTransitionVectors = {
    readonly schemaVersion: 1;
    readonly validTransitions: readonly LifecycleTransitionVector[];
    readonly invalidTransitions: readonly LifecycleTransitionVector[];
};

type CapabilityVector = {
    readonly caseName: string;
    readonly action: ProtocolAction;
    readonly context: Omit<CapabilityContext, 'thresholdProfile'>;
    readonly expected: ReturnType<typeof evaluateActionCapability>;
    readonly thresholdProfileInput?: ThresholdProfileInput;
};

type CapabilityVectors = {
    readonly schemaVersion: 1;
    readonly cases: readonly CapabilityVector[];
};

type BoardFinalityVectors = {
    readonly schemaVersion: 1;
    readonly mandatoryTargetFinalityPolicy: {
        readonly witnessTotal: 7;
        readonly witnessQuorum: 5;
        readonly conflictingFinalizedHeadsImplyEquivocatingWitnesses: 3;
    };
    readonly coverageCases: readonly {
        readonly caseName: string;
        readonly category:
            | 'board-consistency'
            | 'recovery'
            | 'roster-manifest'
            | 'signed-root'
            | 'target-finality'
            | 'target-acceptance';
        readonly expectedOk: boolean;
        readonly expectedRefusalCodes: readonly string[];
        readonly expectedEquivocatingWitnessCount?: number;
    }[];
    readonly requiredHashNamespaces: readonly string[];
    readonly firstValidOrdering: FirstValidOrderingInput & {
        readonly expectedOrderedObjectHashes: readonly string[];
    };
    readonly negativeFirstValidOrderings: readonly (FirstValidOrderingInput & {
        readonly caseName: string;
        readonly expectedRefusalCodes: readonly string[];
    })[];
};

type DeterministicFixtureVectors = {
    readonly schemaVersion: 1;
    readonly caseName: string;
    readonly signature: {
        readonly envelope: ProtocolSignatureEnvelope;
        readonly expectedSignatureHash: string;
        readonly expectedVerification: Pick<
            SignatureVerificationResult,
            'acceptedHashes' | 'ok' | 'refusedObjects'
        >;
    };
    readonly board: {
        readonly input: BoardConsistencyInput;
        readonly expectedVerification: Pick<
            ReturnType<typeof verifyBoardConsistency>,
            'acceptedHashes' | 'ok' | 'refusedObjects' | 'verifiedHeadHashes'
        >;
    };
    readonly rosterManifest: {
        readonly input: RosterManifestTranscriptInput;
        readonly expectedVerification: Pick<
            ReturnType<typeof verifyRosterManifestTranscript>,
            | 'acceptedHashes'
            | 'electionManifestHash'
            | 'ok'
            | 'refusedObjects'
            | 'rosterHash'
        >;
    };
    readonly targetFinality: {
        readonly input: TargetFinalityVerificationInput;
        readonly expectedVerification: Pick<
            ReturnType<typeof verifyTargetFinality>,
            | 'acceptedHashes'
            | 'equivocatingWitnessIdentities'
            | 'ok'
            | 'refusedObjects'
            | 'targetFinalityCheckpointHash'
            | 'targetFinalityRecordHash'
            | 'targetProposalHash'
            | 'validWitnessIdentities'
        >;
    };
    readonly recovery: {
        readonly input: RecoveryEpochVerificationInput;
        readonly expectedVerification: Pick<
            ReturnType<typeof verifyRecoveryEpochUpdate>,
            'acceptedHashes' | 'ok' | 'refusedObjects' | 'updatedEntry'
        >;
    };
};

const thresholdProfiles = thresholdProfilesJson as ThresholdProfileVectors;
const pollSpecs = pollSpecsJson as PollSpecVectors;
const lifecycleTransitions =
    lifecycleTransitionsJson as LifecycleTransitionVectors;
const capabilityRefusals = capabilityRefusalsJson as CapabilityVectors;
const boardFinality = boardFinalityJson as unknown as BoardFinalityVectors;
const deterministicFixtures =
    deterministicFixturesJson as unknown as DeterministicFixtureVectors;
const currentBridgeAndEvaluatorNamespaces = [
    'EncryptedAggregateBridgeHash',
    'EncryptedAggregateInputRoot',
    'EncryptedAggregateShareCiphertextRoot',
    'EncryptedAggregateReconstructionHash',
    'BridgeWitnessPrivacyProfileHash',
    'ScoreBitDerivationCircuitHash',
    'EncryptedScoreBitInputHash',
    'ComparisonInputDerivationCircuitHash',
    'EncryptedComparisonInputHash',
] as const;

describe('election foundation test vectors', () => {
    it('matches deterministic threshold-profile vectors', () => {
        for (const vector of thresholdProfiles.profiles) {
            expect(
                deriveThresholdProfile(vector.input),
                vector.caseName,
            ).toEqual(vector.expected);
        }
    });

    it('matches poll-spec validation vectors', () => {
        for (const vector of pollSpecs.cases) {
            const validation = validatePollSpec(vector.input);

            expect(validation.ok, vector.caseName).toBe(vector.expectedOk);
            if (!validation.ok) {
                expect(validation.errors.map((error) => error.code)).toEqual(
                    vector.expectedErrorCodes,
                );
            }
        }
    });

    it('matches lifecycle transition vectors', () => {
        for (const transition of lifecycleTransitions.validTransitions) {
            expect(isValidLifecycleTransition(transition)).toBe(true);
        }
        for (const transition of lifecycleTransitions.invalidTransitions) {
            expect(isValidLifecycleTransition(transition)).toBe(false);
        }
    });

    it('matches capability refusal vectors against their threshold profiles', () => {
        for (const vector of capabilityRefusals.cases) {
            const thresholdProfile = deriveThresholdProfile(
                vector.thresholdProfileInput ?? { rosterSize: 20 },
            );

            expect(
                evaluateActionCapability(vector.action, {
                    ...vector.context,
                    thresholdProfile,
                }),
                vector.caseName,
            ).toEqual(vector.expected);
        }
    });

    it('matches board-finality and first-valid vectors', () => {
        expect(boardFinality.mandatoryTargetFinalityPolicy).toEqual({
            witnessTotal: 7,
            witnessQuorum: 5,
            conflictingFinalizedHeadsImplyEquivocatingWitnesses: 3,
        });
        expect(
            boardFinality.coverageCases.map((testCase) => testCase.caseName),
        ).toEqual([
            'honest-board-chain-with-inclusion',
            'fabricated-inclusion-proof',
            'non-ancestor-consistency-proof',
            'forked-board-heads',
            'signed-root-missing-required-field',
            'honest-target-finality-5-of-7',
            'target-finality-too-few-witnesses',
            'target-finality-duplicate-witness',
            'target-finality-unknown-witness',
            'target-finality-conflicting-finalized-heads',
            'local-replay-without-finality',
            'target-accepted-record-missing-evaluation-proof',
            'decryption-share-wrong-accepted-target',
            'honest-roster-manifest',
            'duplicate-registration',
            'late-registration',
            'conflicting-board-included-manifest',
            'recovery-update-conflict',
            'stale-recovery-action',
        ]);
        expect(
            boardFinality.coverageCases.find(
                (testCase) =>
                    testCase.caseName ===
                    'target-finality-conflicting-finalized-heads',
            ),
        ).toMatchObject({
            expectedRefusalCodes: ['BoardForkDetected'],
            expectedEquivocatingWitnessCount: 5,
        });
        for (const namespace of boardFinality.requiredHashNamespaces) {
            expect(protocolHashNamespaceValues).toContain(namespace);
        }
        expect(boardFinality.requiredHashNamespaces).toEqual(
            expect.arrayContaining([...currentBridgeAndEvaluatorNamespaces]),
        );

        const { expectedOrderedObjectHashes, ...orderingInput } =
            boardFinality.firstValidOrdering;
        const ordering = deriveValidatedFirstValidOrder(orderingInput);

        expect(ordering.ok).toBe(true);
        expect(
            ordering.orderedObjects.map((object) => object.objectHash),
        ).toEqual(expectedOrderedObjectHashes);

        for (const vector of boardFinality.negativeFirstValidOrderings) {
            const result = deriveValidatedFirstValidOrder(vector);

            expect(
                result.refusedObjects.map((refusal) => refusal.code),
                vector.caseName,
            ).toEqual(expect.arrayContaining([...vector.expectedRefusalCodes]));
        }
    });

    it('matches deterministic signed board, roster, finality, recovery, and signature fixtures', () => {
        expect(deterministicFixtures.caseName).toBe(
            'deterministic-signed-fixtures',
        );

        const { envelope } = deterministicFixtures.signature;
        expect(envelope.signatureHash).toBe(
            deterministicFixtures.signature.expectedSignatureHash,
        );
        expect(
            verifySignedObjectSignature(envelope, {
                objectType: envelope.signedRoot.objectType,
                objectVersion: envelope.signedRoot.objectVersion,
                signerRole: envelope.signedRoot.signerRole,
                signerIdentity: envelope.signedRoot.signerIdentity,
                ceremonyId: envelope.signedRoot.ceremonyId,
                publicKeyHash: envelope.publicKeyHash,
                manifestHash: envelope.signedRoot.manifestHash,
                objectRoot: envelope.signedRoot.objectRoot,
                boardHeadHash: envelope.signedRoot.boardHeadHash,
                contextHash: envelope.signedRoot.contextHash,
            }),
        ).toMatchObject(deterministicFixtures.signature.expectedVerification);

        const verificationCases: readonly [
            string,
            StructuredProtocolVerificationResult,
            Pick<
                StructuredProtocolVerificationResult,
                'acceptedHashes' | 'ok' | 'refusedObjects'
            >,
        ][] = [
            [
                'board',
                verifyBoardConsistency(deterministicFixtures.board.input),
                deterministicFixtures.board.expectedVerification,
            ],
            [
                'roster-manifest',
                verifyRosterManifestTranscript(
                    deterministicFixtures.rosterManifest.input,
                ),
                deterministicFixtures.rosterManifest.expectedVerification,
            ],
            [
                'target-finality',
                verifyTargetFinality(
                    deterministicFixtures.targetFinality.input,
                ),
                deterministicFixtures.targetFinality.expectedVerification,
            ],
            [
                'recovery',
                verifyRecoveryEpochUpdate(deterministicFixtures.recovery.input),
                deterministicFixtures.recovery.expectedVerification,
            ],
        ];

        for (const [
            caseName,
            actualVerification,
            expectedVerification,
        ] of verificationCases) {
            expect(actualVerification, caseName).toMatchObject(
                expectedVerification,
            );
            expect(actualVerification.refusedObjects, caseName).toEqual([]);
        }
    });
});
