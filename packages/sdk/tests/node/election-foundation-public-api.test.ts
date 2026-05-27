import { readFile } from 'node:fs/promises';

import {
    cpadProfileId,
    targetBoundShareSelectionProfileId,
    type CapabilityContext,
    type CapabilityDecision,
    type FirstValidOrderingInput,
    type FirstValidOrderingVerification,
    type LifecycleLabelInput,
    type LifecycleLabels,
    type LifecycleTransition,
    type PollSpecInput,
    type PollSpecValidation,
    type ProtocolAction,
    type ThresholdProfile,
    type ThresholdProfileInput,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';
import publicSurface from '../../public-surface.json' with { type: 'json' };

type DeriveThresholdProfile = (
    input: ThresholdProfileInput,
) => ThresholdProfile;
type ValidatePollSpec = (input: PollSpecInput) => PollSpecValidation;
type IsValidLifecycleTransition = (transition: LifecycleTransition) => boolean;
type DeriveLifecycleLabels = (input: LifecycleLabelInput) => LifecycleLabels;
type EvaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
) => CapabilityDecision;
type DeriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
) => FirstValidOrderingVerification;
type VerifyBridgeProof = (
    input: Record<string, unknown>,
) => Promise<Record<string, unknown>>;

const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const deriveThresholdProfile =
    publicApiRuntimeRecord.deriveThresholdProfile as DeriveThresholdProfile;
const validatePollSpec =
    publicApiRuntimeRecord.validatePollSpec as ValidatePollSpec;
const isValidLifecycleTransition =
    publicApiRuntimeRecord.isValidLifecycleTransition as IsValidLifecycleTransition;
const deriveLifecycleLabels =
    publicApiRuntimeRecord.deriveLifecycleLabels as DeriveLifecycleLabels;
const evaluateActionCapability =
    publicApiRuntimeRecord.evaluateActionCapability as EvaluateActionCapability;
const deriveValidatedFirstValidOrder =
    publicApiRuntimeRecord.deriveValidatedFirstValidOrder as DeriveValidatedFirstValidOrder;
const verifyBridgeProof =
    publicApiRuntimeRecord.verifyBridgeProof as VerifyBridgeProof;

const requiredPublicFunctions = [
    [
        'deriveFrozenRosterProfile',
        publicApiRuntimeRecord.deriveFrozenRosterProfile,
    ],
    ['deriveLifecycleLabels', deriveLifecycleLabels],
    ['derivePollSpecDigest', publicApiRuntimeRecord.derivePollSpecDigest],
    ['deriveThresholdProfile', deriveThresholdProfile],
    [
        'deriveThresholdProfileDigest',
        publicApiRuntimeRecord.deriveThresholdProfileDigest,
    ],
    ['deriveValidatedFirstValidOrder', deriveValidatedFirstValidOrder],
    ['evaluateActionCapability', evaluateActionCapability],
    [
        'isActionCurrentForRecoveryEpoch',
        publicApiRuntimeRecord.isActionCurrentForRecoveryEpoch,
    ],
    ['isValidLifecycleTransition', isValidLifecycleTransition],
    ['validatePollSpec', validatePollSpec],
    [
        'verifyAggregateDerivationComponent',
        publicApiRuntimeRecord.verifyAggregateDerivationComponent,
    ],
    ['verifyBallotProof', publicApiRuntimeRecord.verifyBallotProof],
    ['verifyBoardConsistency', publicApiRuntimeRecord.verifyBoardConsistency],
    ['verifyBridgeProof', publicApiRuntimeRecord.verifyBridgeProof],
    ['verifyCastReceiptShell', publicApiRuntimeRecord.verifyCastReceiptShell],
    [
        'verifyClaimBearingBallotPackage',
        publicApiRuntimeRecord.verifyClaimBearingBallotPackage,
    ],
    ['verifyCloseRecordShell', publicApiRuntimeRecord.verifyCloseRecordShell],
    ['verifyFirstValidPolicy', publicApiRuntimeRecord.verifyFirstValidPolicy],
    [
        'verifyOneShotSharePolicy',
        publicApiRuntimeRecord.verifyOneShotSharePolicy,
    ],
    ['verifyReceiverKeyProof', publicApiRuntimeRecord.verifyReceiverKeyProof],
    [
        'verifyRecoveryEpochUpdate',
        publicApiRuntimeRecord.verifyRecoveryEpochUpdate,
    ],
    [
        'verifyRosterExternalAcceptance',
        publicApiRuntimeRecord.verifyRosterExternalAcceptance,
    ],
    [
        'verifyRosterManifestTranscript',
        publicApiRuntimeRecord.verifyRosterManifestTranscript,
    ],
    ['verifyTargetFinality', publicApiRuntimeRecord.verifyTargetFinality],
    ['verifyTranscript', publicApiRuntimeRecord.verifyTranscript],
    [
        'verifyTranscriptCoreFixture',
        publicApiRuntimeRecord.verifyTranscriptCoreFixture,
    ],
] as const;

const allowedRuntimeExports = [...publicSurface.runtimeExports].sort();
const forbiddenPublicKeys = publicSurface.forbiddenRuntimeExports;
const lowerHexSha256Pattern = /^[a-f0-9]{64}$/u;

describe('election foundation public package API in Node', () => {
    it('exposes only the safe runtime functions and keeps forbidden operations absent', () => {
        expect(
            requiredPublicFunctions.map(
                ([publicFunctionName]) => publicFunctionName,
            ),
        ).toEqual(publicSurface.runtimeExports);
        expect(Object.keys(publicApiRuntimeRecord).sort()).toEqual(
            allowedRuntimeExports,
        );
        for (const [
            publicFunctionName,
            publicFunction,
        ] of requiredPublicFunctions) {
            expect(typeof publicFunction, publicFunctionName).toBe('function');
        }
        for (const publicKey of forbiddenPublicKeys) {
            expect(publicKey in publicApiRuntimeRecord).toBe(false);
        }
    });

    it('exposes the public bridge verifier without upgrading claim closure', async () => {
        const verification = await verifyBridgeProof({
            aggregateDerivationComponent: {},
            aggregateSelectionPolicyDigest: 'not-a-digest',
            bridgeEncryption: {},
            bridgeWitnessPrivacyProfileDigest: 'not-a-digest',
            heParamDigest: 'not-a-digest',
            setupPackage: {},
        });

        expect(verification).toMatchObject({
            acceptedDigests: [],
            ok: false,
            operation: 'verifyAggregateBridgeEncryption',
            statusLabels: [],
            unresolvedReason: expect.any(String) as string,
        });
        expect(verification.refusedObjects).toEqual([
            expect.objectContaining({
                code: 'BallotPackageInvalid',
                message:
                    'bridgeEncryption.privateMaterialDisclosure is required',
            }),
        ]);
        expect(verification).not.toMatchObject({
            bridgeClaimClosureVerified: true,
        });
    });

    it('keeps the packaged bridge verifier kernel pinned', async () => {
        const kernelLoaderSource = await readFile(
            new URL('../../dist/kernel.js', import.meta.url),
            'utf8',
        );
        const digestMatch =
            /packagedTranscriptCoreKernelNormalizedSha256Hex\s*=\s*'(?<digest>[a-f0-9]{64})'/u.exec(
                kernelLoaderSource,
            );

        expect(digestMatch?.groups?.digest).toMatch(lowerHexSha256Pattern);
        expect(kernelLoaderSource).not.toContain(
            'packagedTranscriptCoreKernelNormalizedSha256Hex =\n    undefined',
        );
    });

    it('derives threshold, poll, lifecycle, label, and capability decisions', () => {
        const thresholdProfile = deriveThresholdProfile({
            rosterSize: 20,
            targetBoundShareSelectionProfile: {
                profileId: targetBoundShareSelectionProfileId,
                certificateDigest: 'target-bound-certificate-digest',
                cpadProfileId,
                targetBasisDigest: 'target-basis-digest',
                decryptionShareQuorum: 9,
                minimumSharesForInterpolation: 7,
                minimumArrivalsForRobustDecode: 9,
                invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
                selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
            },
        });

        expect(thresholdProfile.privacyCorruptionBound).toBe(6);
        expect(
            validatePollSpec({
                pollId: 'poll',
                question: 'Question',
                options: ['A', 'B'],
                topOptionCount: 1,
            }),
        ).toMatchObject({ ok: true });
        expect(
            isValidLifecycleTransition({
                from: 'votingOpen',
                to: 'votingClosed',
            }),
        ).toBe(true);
        const labels = deriveLifecycleLabels({
            lifecycleState: 'fullyVerified',
            thresholdProfile,
            mheSecurityClosure: 'activeMalicious',
            localRosterAccepted: true,
            runtimeClaimGatePassed: true,
            bridgeBenchmarkReportPresent: true,
            bridgeProverCertificatePresent: true,
            evaluationProofCertificatePresent: true,
            oneShotDecryptionProofCertificatePresent: true,
            kllpsCpadCertificatePresent: true,
            thresholdDecryptionCertificatePresent: true,
            evaluationProofClosureApplied: true,
            kllpsCpadClosureApplied: true,
            activeMaliciousClosureApplied: true,
            decodedResultLayoutVerified: true,
        });

        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
        expect(labels.modes).toEqual([]);
        expect(
            evaluateActionCapability('AcceptTarget', {
                lifecycleState: 'evaluationProofVerified',
                thresholdProfile,
                pollSpecValid: true,
                localRosterAccepted: true,
                rosterExternalAcceptanceDigest: 'accepted-roster-digest',
                actionContextRosterExternalAcceptanceDigest:
                    'accepted-roster-digest',
                targetFinalityAccepted: true,
                evaluationProofVerified: true,
                bridgeBenchmarkReportPresent: true,
            }),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
        expect(
            deriveValidatedFirstValidOrder({
                requiredContextDigest: 'context',
                selectionPolicyDigest: 'policy',
                expectedSelectionPolicyDigest: 'policy',
                currentRecoveryEpochMap: {
                    participant: {
                        signerIdentity: 'participant',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                objects: [
                    {
                        objectDigest: 'candidate',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextDigest: 'context',
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }),
        ).toMatchObject({
            ok: true,
            orderedObjects: [
                expect.objectContaining({ objectDigest: 'candidate' }),
            ],
        });
    });
});
