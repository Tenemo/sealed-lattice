import { describe, expect, it } from 'vitest';
import { commands } from 'vitest/browser';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

// Manual desktop-Chromium measurement lane for the public-key share argument
// at first-profile scale. The public-key share family reuses the unified
// trustee evaluation-key succinct argument: it opens the single accepted
// limb-zero same-secret constant commitment and binds one public-key
// component column. The lane records browser WASM development evidence only;
// it is not supported-phone evidence and it must stay out of the default
// browser test runner.
const firstProfileRingDegree = 32_768;
const firstProfileRnsLimbCount = 17;
const commitmentRandomnessColumnCount = 5;
const benchmarkTrusteeIdentity = 'trustee-0';
const benchmarkTrusteeRosterPosition = 0;
const protocolHashPattern = /^[a-f0-9]{128}$/u;

const zeroU64Vector = (): number[] =>
    Array.from({ length: firstProfileRingDegree }, () => 0);

const zeroI64Vector = (): number[] =>
    Array.from({ length: firstProfileRingDegree }, () => 0);

const zeroOpeningRandomness = (): number[][] =>
    Array.from({ length: commitmentRandomnessColumnCount }, () =>
        zeroI64Vector(),
    );

describe('public-key share browser measurement', () => {
    it('measures first-profile public-key share prove and verify in desktop browser WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const bgvProfile = kernel.describeBgvRnsProfile();
        const qSharePrimes = bgvProfile.profile.dataPrimes;
        expect(bgvProfile.profile.polynomialDegree).toBe(
            firstProfileRingDegree,
        );
        expect(qSharePrimes).toHaveLength(firstProfileRnsLimbCount);
        const limbZeroPrime = qSharePrimes[0];
        if (limbZeroPrime === undefined) {
            throw new Error('Collective setup profile must expose Q_share primes.');
        }

        const fixtureHash = (label: string): string =>
            kernel.deriveProtocolHash({
                namespace: 'ActionContextHash',
                value: {
                    fixture: 'public-key-share-browser-measurement',
                    label,
                },
            });
        // The public-key share family links to a single limb-zero same-secret
        // constant commitment; the linkage seed is domain-separated from the
        // anchor public-matrix seed in the accepted setup graph.
        const publicMatrixSeedHash = fixtureHash('public-key-linkage-seed');

        // The public-key relation binds b = -a*s + e over the accepted
        // public-A key-switch domain. A trivial well-formed witness keeps the
        // single component column consistent with the limb-zero commitment so
        // the lane measures the full first-profile prove and verify cost
        // without hand-deriving a key-switch component matrix.
        const commitmentSetupStart = performance.now();
        const linkageCommitmentResponse =
            kernel.computeSetupCommitmentFromOpening({
                publicMatrixSeedHash,
                sourceRnsLimbIndex: 0,
                sourceMessageModulus: limbZeroPrime,
                shamirCoefficientIndex: 0,
                messageCoefficients: zeroU64Vector(),
                randomnessByColumn: zeroOpeningRandomness(),
                ringDegree: firstProfileRingDegree,
            });
        expect(linkageCommitmentResponse.ok).toBe(true);
        const commitmentSetupMilliseconds = Math.round(
            performance.now() - commitmentSetupStart,
        );

        const statementContext = {
            ceremonyId: 'public-key-share-browser-measurement-ceremony',
            manifestHash: fixtureHash('manifest'),
            rosterHash: fixtureHash('roster'),
            trusteeIdentity: benchmarkTrusteeIdentity,
            trusteeRosterPosition: benchmarkTrusteeRosterPosition,
            setupEpoch: 'setup-epoch-1',
            sameSecretStatementRoot: fixtureHash('same-secret-statement-root'),
            sameSecretProofRoot: fixtureHash('same-secret-proof-root'),
        } as const;
        const sameSecretLinkage = {
            publicMatrixSeedHash,
            commitments: [linkageCommitmentResponse.commitment],
        } as const;
        const publicKeyShareKey = {
            proofFamily: 'public-key-share',
            level: qSharePrimes.length - 1,
            keySwitchDomain: 'accepted-bgv-public-a',
            keySwitchSeedHex: publicMatrixSeedHash,
            componentBByDigit: [qSharePrimes.map(() => zeroU64Vector())],
        } as const;
        const generateInput = {
            context: statementContext,
            ringDegree: firstProfileRingDegree,
            keys: [publicKeyShareKey],
            sameSecretLinkage,
            secretCoefficients: zeroI64Vector(),
            errorCoefficientsByKey: [[zeroI64Vector()]],
            negativeIndicatorCoefficients: zeroI64Vector(),
            openingRandomnessByLimb: [zeroOpeningRandomness()],
            proofRandomnessSource: 'development-deterministic-fixture',
            proofRandomnessSeedHex: fixtureHash('proof-randomness-seed'),
            proofRandomnessNonceHex: fixtureHash('proof-randomness-nonce'),
        } as const;
        const proveRequestByteLength = new TextEncoder().encode(
            JSON.stringify(generateInput),
        ).byteLength;

        const proveStart = performance.now();
        const generatedProof =
            kernel.generateTrusteeEvaluationKeyProof(generateInput);
        const proveMilliseconds = Math.round(performance.now() - proveStart);

        expect(generatedProof.ok).toBe(true);
        expect(generatedProof.proofFamily).toBe('public-key-share');
        expect(generatedProof.keyCount).toBe(1);
        expect(generatedProof.sameSecretLinkageIncluded).toBe(true);
        expect(generatedProof.statementHash).toMatch(protocolHashPattern);

        const verifyStart = performance.now();
        const verifiedProof = kernel.verifyTrusteeEvaluationKeyProof({
            context: statementContext,
            ringDegree: firstProfileRingDegree,
            keys: [publicKeyShareKey],
            sameSecretLinkage,
            proofBytesHex: generatedProof.proofBytesHex,
        });
        const verifyMilliseconds = Math.round(performance.now() - verifyStart);

        expect(verifiedProof.ok).toBe(true);
        expect(verifiedProof.proofFamily).toBe('public-key-share');
        expect(verifiedProof.statementHash).toBe(generatedProof.statementHash);
        expect(verifiedProof.proofByteLength).toBe(
            generatedProof.proofByteLength,
        );

        const measurementRow = {
            measurementLane: 'desktop-chromium-browser-wasm',
            evidenceBoundary:
                'development desktop browser evidence; not supported-phone evidence',
            proofFamily: 'public-key-share',
            ringDegree: firstProfileRingDegree,
            rnsLimbCount: qSharePrimes.length,
            keyCount: generatedProof.keyCount,
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
            `public-key-share-browser-measurement ${JSON.stringify(measurementRow)}`,
        );
        await commands.writeFile(
            'temp/browser-proof-benchmark/public-key-share-measurement.json',
            `${JSON.stringify(measurementRow, null, 4)}\n`,
        );
    });
});
