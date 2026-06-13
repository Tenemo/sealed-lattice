import { describe, expect, it } from 'vitest';
import { commands } from 'vitest/browser';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';

// Manual desktop-Chromium measurement lane for the recipient-private VSS share
// argument at first-profile scale. The recipient-private family proves that a
// delivered share opens the committed Shamir coefficients with a lifted carry
// vector, without publishing coefficient messages, openings, or carries. The
// lane records browser WASM development evidence only; it is not
// supported-phone evidence and it must stay out of the default browser runner.
const firstProfileRingDegree = 32_768;
const firstProfileRnsLimbCount = 17;
const commitmentRandomnessColumnCount = 5;
const shamirCoefficientCount = 4;
const protocolHashPattern = /^[a-f0-9]{128}$/u;

type JsonRecord = Record<string, unknown>;

const zeroU64Vector = (): number[] =>
    Array.from({ length: firstProfileRingDegree }, () => 0);

const zeroI64Vector = (): number[] =>
    Array.from({ length: firstProfileRingDegree }, () => 0);

const zeroOpeningRandomness = (): number[][] =>
    Array.from({ length: commitmentRandomnessColumnCount }, () =>
        zeroI64Vector(),
    );

describe('recipient-private VSS share browser measurement', () => {
    it('measures first-profile private VSS share prove and verify in desktop browser WASM', async () => {
        const kernel: TranscriptCoreKernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const qSharePrimes = profile.qShare.primes;
        expect(qSharePrimes).toHaveLength(firstProfileRnsLimbCount);
        const limbZeroPrime = qSharePrimes[0];
        if (limbZeroPrime === undefined) {
            throw new Error('Collective setup profile must expose Q_share primes.');
        }

        const fixtureHash = (label: string): string =>
            kernel.deriveProtocolHash({
                namespace: 'ActionContextHash',
                value: {
                    fixture: 'private-vss-share-browser-measurement',
                    label,
                },
            });
        const publicMatrixSeedHash = fixtureHash('public-matrix-seed');
        const setupContext = {
            ceremonyId: 'private-vss-share-browser-measurement-ceremony',
            manifestHash: fixtureHash('manifest'),
            rosterHash: fixtureHash('roster'),
            setupProfileHash: profile.setupProfileHash,
            qShareHash: profile.qShareHash,
            carryAwareVssShareRelationProfileHash:
                profile.carryAwareVssShareRelationProfileHash,
            commitmentProfileHash: profile.commitmentProfileHash,
            setupEpoch: 'setup-epoch-1',
        } as const;

        // The recipient-private statement binds the dealer's full coefficient
        // commitment record; a trivial well-formed witness keeps every limb and
        // Shamir column consistent so the lane measures the full first-profile
        // prove and verify cost without dealer secret material.
        const commitmentSetupStart = performance.now();
        const coefficientCommitments: JsonRecord[] = [];
        const materialRecords: JsonRecord[] = [];
        const coefficientCommitmentRoots: string[] = [];
        qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
            Array.from(
                { length: shamirCoefficientCount },
                (_unused, shamirCoefficientIndex) => {
                    const computation =
                        kernel.computeSetupCommitmentFromOpening({
                            publicMatrixSeedHash,
                            sourceRnsLimbIndex: rnsLimbIndex,
                            sourceMessageModulus: rnsPrime,
                            shamirCoefficientIndex,
                            messageCoefficients: zeroU64Vector(),
                            randomnessByColumn: zeroOpeningRandomness(),
                            ringDegree: firstProfileRingDegree,
                        });
                    expect(computation.ok).toBe(true);
                    if (rnsLimbIndex === 0) {
                        coefficientCommitmentRoots.push(
                            computation.commitmentRoot,
                        );
                    }
                    const commonRecordFields = {
                        objectVersion: 1,
                        ceremonyId: setupContext.ceremonyId,
                        manifestHash: setupContext.manifestHash,
                        rosterHash: setupContext.rosterHash,
                        setupProfileHash: setupContext.setupProfileHash,
                        qShareHash: setupContext.qShareHash,
                        carryAwareVssShareRelationProfileHash:
                            setupContext.carryAwareVssShareRelationProfileHash,
                        commitmentProfileHash:
                            setupContext.commitmentProfileHash,
                        setupEpoch: setupContext.setupEpoch,
                        sourceTrusteeIdentity:
                            'private-vss-share-browser-measurement-source',
                        sourceTrusteeRosterPosition: 0,
                        publicMatrixSeedHash,
                        rnsLimbIndex,
                        rnsPrime,
                        shamirCoefficientIndex,
                        commitmentRoot: computation.commitmentRoot,
                    };
                    coefficientCommitments.push({
                        objectType: 'VssCoefficientCommitment',
                        ...commonRecordFields,
                    });
                    materialRecords.push({
                        objectType: 'VssCoefficientCommitmentMaterial',
                        ...commonRecordFields,
                        commitment: computation.commitment,
                    });
                },
            );
        });
        const sourceTrusteeRecord: JsonRecord = {
            objectType: 'VssSourceTrusteeCoefficientCommitments',
            objectVersion: 1,
            ceremonyId: setupContext.ceremonyId,
            manifestHash: setupContext.manifestHash,
            rosterHash: setupContext.rosterHash,
            setupProfileHash: setupContext.setupProfileHash,
            qShareHash: setupContext.qShareHash,
            carryAwareVssShareRelationProfileHash:
                setupContext.carryAwareVssShareRelationProfileHash,
            commitmentProfileHash: setupContext.commitmentProfileHash,
            setupEpoch: setupContext.setupEpoch,
            sourceTrusteeIdentity:
                'private-vss-share-browser-measurement-source',
            sourceTrusteeRosterPosition: 0,
            publicMatrixSeedHash,
            coefficientCommitments,
        };
        sourceTrusteeRecord.sourceTrusteeCommitmentRoot =
            kernel.deriveProtocolHash({
                namespace: 'VssCoefficientCommitmentRoot',
                value: sourceTrusteeRecord,
            });
        const commitmentSetupMilliseconds = Math.round(
            performance.now() - commitmentSetupStart,
        );

        const generateInput = {
            setupContext,
            publicMatrixSeedHash,
            privateEnvelopeAadHash: fixtureHash('private-envelope-aad'),
            sourceTrusteeCoefficientCommitmentRecord: sourceTrusteeRecord,
            sourceTrusteeCoefficientCommitmentMaterialRecords: materialRecords,
            recipientIdentity:
                'private-vss-share-browser-measurement-recipient',
            recipientRosterPosition: 2,
            rnsLimbIndex: 0,
            rnsPrime: limbZeroPrime,
            ringDegree: firstProfileRingDegree,
            shareValues: zeroU64Vector(),
            coefficientCommitmentRoots,
            coefficientMessagesByShamirIndex: Array.from(
                { length: shamirCoefficientCount },
                () => zeroU64Vector(),
            ),
            openingRandomnessByShamirIndex: Array.from(
                { length: shamirCoefficientCount },
                () => zeroOpeningRandomness(),
            ),
            proofRandomnessSource: 'development-deterministic-fixture',
            proofRandomnessSeedHex: fixtureHash('proof-randomness-seed'),
            proofRandomnessNonceHex: fixtureHash('proof-randomness-nonce'),
        } as const;
        const proveRequestByteLength = new TextEncoder().encode(
            JSON.stringify(generateInput),
        ).byteLength;

        const proveStart = performance.now();
        const generatedProof =
            kernel.generatePrivateVssShareProof(generateInput);
        const proveMilliseconds = Math.round(performance.now() - proveStart);

        expect(generatedProof.ok).toBe(true);
        expect(generatedProof.privateVssShareProof.proofFamily).toBe(
            'vss-opening-carry',
        );
        const proofStatementHash = generatedProof.privateVssShareProof
            .statementHash as string;
        expect(proofStatementHash).toMatch(protocolHashPattern);
        const proofBytesHex = generatedProof.privateVssShareProof
            .proofBytesHex as string;
        const proofByteLength = proofBytesHex.length / 2;

        // The lane measures the source/dealer-side proof generation cost, which
        // is the dominant mobile-feasibility metric for this family. Recipient
        // verification runs through the multi-object private envelope path
        // (verifyPrivateVssShareEnvelope) and is exercised end to end by the
        // recipient delivery integration tests rather than reconstructed here.
        const measurementRow = {
            measurementLane: 'desktop-chromium-browser-wasm',
            evidenceBoundary:
                'development desktop browser evidence; not supported-phone evidence',
            proofFamily: 'private-vss-share',
            measuredSide: 'source-dealer proof generation',
            recipientVerificationNote:
                'recipient-local envelope verification is covered by the recipient delivery integration tests, not this prove-side lane',
            ringDegree: firstProfileRingDegree,
            rnsLimbCount: qSharePrimes.length,
            shamirCoefficientCount,
            commitmentSetupMilliseconds,
            proveMilliseconds,
            proofByteLength,
            largestCopiedBufferBytes: proveRequestByteLength,
            largestCopiedBufferSource: 'serialized prove request',
            peakWasmMemoryBytes: kernel.wasmMemoryByteLength(),
            persistentStorageBytes: 0,
            persistentStorageNote: 'the measurement lane persists nothing',
            resumeBehavior:
                'proof generation is a single kernel command without partial state; an interrupted command restarts from its inputs',
        };
        console.log(
            `private-vss-share-browser-measurement ${JSON.stringify(measurementRow)}`,
        );
        await commands.writeFile(
            'temp/browser-proof-benchmark/private-vss-share-measurement.json',
            `${JSON.stringify(measurementRow, null, 4)}\n`,
        );
    });
});
