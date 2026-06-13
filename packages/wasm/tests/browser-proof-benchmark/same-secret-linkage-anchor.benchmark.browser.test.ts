import { describe, expect, it } from 'vitest';
import { commands } from 'vitest/browser';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

// Manual desktop-Chromium measurement lane for the keyless same-secret
// linkage-anchor argument at first-profile scale. The lane records browser
// WASM development evidence only; it is not supported-phone evidence and it
// must stay out of the default browser test runner.
const firstProfileRingDegree = 32_768;
const firstProfileRnsLimbCount = 17;
const commitmentRandomnessColumnCount = 5;
const benchmarkTrusteeIdentity = 'trustee-0';
const benchmarkTrusteeRosterPosition = 0;
const protocolHashPattern = /^[a-f0-9]{128}$/u;

// Deterministic ternary fixture values in {-1, 0, 1}; the lane measures
// runtime, so any well-formed witness works, but determinism keeps repeated
// measurements comparable.
const ternaryFixtureValue = (selector: number): number => (selector % 3) - 1;

const secretCoefficientFixture = (coefficientPosition: number): number =>
    ternaryFixtureValue(coefficientPosition * 7 + 1);

const openingRandomnessFixture = (
    rnsLimbIndex: number,
    randomnessColumnIndex: number,
    coefficientPosition: number,
): number =>
    ternaryFixtureValue(
        rnsLimbIndex * 13 +
            randomnessColumnIndex * 5 +
            coefficientPosition * 3 +
            2,
    );

describe('same-secret linkage anchor browser measurement', () => {
    it('measures first-profile anchor prove and verify in desktop browser WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const bgvProfile = kernel.describeBgvRnsProfile();
        const qSharePrimes = bgvProfile.profile.dataPrimes;
        expect(bgvProfile.profile.polynomialDegree).toBe(
            firstProfileRingDegree,
        );
        expect(qSharePrimes).toHaveLength(firstProfileRnsLimbCount);

        const fixtureHash = (label: string): string =>
            kernel.deriveProtocolHash({
                namespace: 'ActionContextHash',
                value: {
                    fixture: 'same-secret-linkage-anchor-browser-measurement',
                    label,
                },
            });
        const publicMatrixSeedHash = fixtureHash('public-matrix-seed');

        const secretCoefficients = Array.from(
            { length: firstProfileRingDegree },
            (_unused, coefficientPosition) =>
                secretCoefficientFixture(coefficientPosition),
        );
        const negativeIndicatorCoefficients = secretCoefficients.map(
            (secretCoefficient) => (secretCoefficient < 0 ? 1 : 0),
        );
        const openingRandomnessByLimb = qSharePrimes.map(
            (_unusedPrime, rnsLimbIndex) =>
                Array.from(
                    { length: commitmentRandomnessColumnCount },
                    (_unusedColumn, randomnessColumnIndex) =>
                        Array.from(
                            { length: firstProfileRingDegree },
                            (_unusedCoefficient, coefficientPosition) =>
                                openingRandomnessFixture(
                                    rnsLimbIndex,
                                    randomnessColumnIndex,
                                    coefficientPosition,
                                ),
                        ),
                ),
        );

        // The anchor statement carries one accepted BDLOP constant commitment
        // per Q_share limb; the same kernel computes them from the witness
        // openings, so the lane is self-contained.
        const commitmentSetupStart = performance.now();
        const constantCommitments = qSharePrimes.map(
            (sourceMessageModulus, rnsLimbIndex) => {
                const messageCoefficients = secretCoefficients.map(
                    (secretCoefficient) =>
                        secretCoefficient >= 0
                            ? secretCoefficient
                            : sourceMessageModulus + secretCoefficient,
                );
                const commitmentResponse =
                    kernel.computeSetupCommitmentFromOpening({
                        publicMatrixSeedHash,
                        sourceRnsLimbIndex: rnsLimbIndex,
                        sourceMessageModulus,
                        shamirCoefficientIndex: 0,
                        messageCoefficients,
                        randomnessByColumn:
                            openingRandomnessByLimb[rnsLimbIndex] ?? [],
                        ringDegree: firstProfileRingDegree,
                    });
                expect(commitmentResponse.ok).toBe(true);

                return commitmentResponse.commitment;
            },
        );
        const commitmentSetupMilliseconds = Math.round(
            performance.now() - commitmentSetupStart,
        );

        const statementContext = {
            ceremonyId: 'anchor-browser-measurement-ceremony',
            manifestHash: fixtureHash('manifest'),
            rosterHash: fixtureHash('roster'),
            trusteeIdentity: benchmarkTrusteeIdentity,
            trusteeRosterPosition: benchmarkTrusteeRosterPosition,
            setupEpoch: 'setup-epoch-1',
            vssCoefficientCommitmentMaterialRoot: fixtureHash(
                'vss-coefficient-commitment-material-root',
            ),
        } as const;
        const sameSecretLinkage = {
            publicMatrixSeedHash,
            commitments: constantCommitments,
        } as const;
        const generateInput = {
            context: statementContext,
            ringDegree: firstProfileRingDegree,
            keys: [],
            sameSecretLinkage,
            secretCoefficients,
            errorCoefficientsByKey: [],
            negativeIndicatorCoefficients,
            openingRandomnessByLimb,
            proofRandomnessSource: 'development-deterministic-fixture',
            proofRandomnessSeedHex: fixtureHash('proof-randomness-seed'),
        } as const;
        const proveRequestByteLength = new TextEncoder().encode(
            JSON.stringify(generateInput),
        ).byteLength;

        const proveStart = performance.now();
        const generatedProof =
            kernel.generateTrusteeEvaluationKeyProof(generateInput);
        const proveMilliseconds = Math.round(performance.now() - proveStart);

        expect(generatedProof.ok).toBe(true);
        expect(generatedProof.proofFamily).toBe('same-secret-linkage-anchor');
        expect(generatedProof.sameSecretLinkageIncluded).toBe(true);
        expect(generatedProof.keyCount).toBe(0);
        expect(generatedProof.statementHash).toMatch(protocolHashPattern);

        const verifyStart = performance.now();
        const verifiedProof = kernel.verifyTrusteeEvaluationKeyProof({
            context: statementContext,
            ringDegree: firstProfileRingDegree,
            keys: [],
            sameSecretLinkage,
            proofBytesHex: generatedProof.proofBytesHex,
        });
        const verifyMilliseconds = Math.round(performance.now() - verifyStart);

        expect(verifiedProof.ok).toBe(true);
        expect(verifiedProof.proofFamily).toBe('same-secret-linkage-anchor');
        expect(verifiedProof.statementHash).toBe(generatedProof.statementHash);
        expect(verifiedProof.proofByteLength).toBe(
            generatedProof.proofByteLength,
        );

        const measurementRow = {
            measurementLane: 'desktop-chromium-browser-wasm',
            evidenceBoundary:
                'development desktop browser evidence; not supported-phone evidence',
            proofFamily: 'same-secret-linkage-anchor',
            ringDegree: firstProfileRingDegree,
            rnsLimbCount: qSharePrimes.length,
            commitmentSetupMilliseconds,
            proveMilliseconds,
            verifyMilliseconds,
            proofByteLength: generatedProof.proofByteLength,
            largestCopiedBufferBytes: proveRequestByteLength,
            largestCopiedBufferSource: 'serialized prove request',
            peakWasmMemoryBytes: kernel.wasmMemoryByteLength(),
            persistentStorageBytes: 0,
            persistentStorageNote: 'the measurement lane persists nothing',
            resumeBehavior:
                'prove and verify are single kernel commands without partial state; an interrupted command restarts from its inputs',
        };
        console.log(
            `same-secret-linkage-anchor-browser-measurement ${JSON.stringify(measurementRow)}`,
        );
        // Browser console output does not reliably reach captured terminal
        // logs, so the lane also persists the measurement row through the
        // vitest server-side file command for the documentation ledger.
        await commands.writeFile(
            'temp/browser-proof-benchmark/same-secret-linkage-anchor-measurement.json',
            `${JSON.stringify(measurementRow, null, 4)}\n`,
        );
    });
});
