import { describe, expect, it } from 'vitest';
import { commands } from 'vitest/browser';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

// Manual desktop-Chromium measurement lane for the trustee evaluation-key
// argument at first-profile scale. A trustee's accepted evaluation-key proof
// batches every key-switch key it contributes (relinearization round one and
// round two plus the scheduled Galois rotations) into one succinct argument.
// This lane measures one representative largest single key (relinearization
// round one at the selected working level), records its per-key cost, and
// records the structural full-batch budget so the full per-trustee batch is not
// silently understated. The lane records browser WASM development evidence
// only; it is not supported-phone evidence and must stay out of the default
// browser test runner.
const firstProfileRingDegree = 32_768;
const firstProfileRnsLimbCount = 17;
// SELECTED_EVALUATOR_WORKING_LEVEL in the kernel; relinearization keys at this
// level carry level + 1 decomposition digits over level + 1 RNS limbs.
const selectedEvaluatorWorkingLevel = 15;
const decompositionDigitCount = selectedEvaluatorWorkingLevel + 1;
const keySwitchLimbCount = selectedEvaluatorWorkingLevel + 1;
const protocolHashPattern = /^[a-f0-9]{128}$/u;

const zeroU64Vector = (): number[] =>
    Array.from({ length: firstProfileRingDegree }, () => 0);

const zeroI64Vector = (): number[] =>
    Array.from({ length: firstProfileRingDegree }, () => 0);

describe('trustee evaluation-key browser measurement', () => {
    it('measures first-profile evaluation-key prove and verify in desktop browser WASM', async () => {
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
                    fixture: 'trustee-evaluation-key-browser-measurement',
                    label,
                },
            });

        // A relinearization round-one key at the selected working level carries
        // level + 1 decomposition digits, each over level + 1 RNS limbs. A
        // trivial well-formed witness (zero secret, zero per-digit error, zero
        // key-switch component) keeps the b = -a*s + e relation consistent so
        // the lane measures the full first-profile prove and verify cost of one
        // representative largest key without hand-deriving real key-switch
        // material.
        const componentSetupStart = performance.now();
        const componentBByDigit = Array.from(
            { length: decompositionDigitCount },
            () =>
                Array.from({ length: keySwitchLimbCount }, () =>
                    zeroU64Vector(),
                ),
        );
        const errorCoefficientsForKey = Array.from(
            { length: decompositionDigitCount },
            () => zeroI64Vector(),
        );
        const componentSetupMilliseconds = Math.round(
            performance.now() - componentSetupStart,
        );

        const statementContext = {
            ceremonyId: 'trustee-evaluation-key-browser-measurement-ceremony',
            manifestHash: fixtureHash('manifest'),
            rosterHash: fixtureHash('roster'),
            trusteeIdentity: 'trustee-0',
            trusteeRosterPosition: 0,
            setupEpoch: 'setup-epoch-1',
            requiredGaloisSetHash: fixtureHash('required-galois-set'),
            evaluatorKeyScheduleRoot: fixtureHash('evaluator-key-schedule-root'),
            keySwitchDecompositionHash: fixtureHash(
                'key-switch-decomposition',
            ),
            sameSecretStatementRoot: fixtureHash('same-secret-statement-root'),
            sameSecretProofRoot: fixtureHash('same-secret-proof-root'),
        } as const;
        const relinearizationRoundOneKey = {
            proofFamily: 'relinearization-round-one',
            level: selectedEvaluatorWorkingLevel,
            keySwitchDomain: 'relinearization-round-one',
            keySwitchSeedHex: fixtureHash('relinearization-round-one-seed'),
            componentBByDigit,
        } as const;
        const generateInput = {
            context: statementContext,
            ringDegree: firstProfileRingDegree,
            keys: [relinearizationRoundOneKey],
            secretCoefficients: zeroI64Vector(),
            errorCoefficientsByKey: [errorCoefficientsForKey],
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
        expect(generatedProof.proofFamily).toBe('trustee-evaluation-key');
        expect(generatedProof.keyCount).toBe(1);
        expect(generatedProof.statementHash).toMatch(protocolHashPattern);

        const verifyStart = performance.now();
        const verifiedProof = kernel.verifyTrusteeEvaluationKeyProof({
            context: statementContext,
            ringDegree: firstProfileRingDegree,
            keys: [relinearizationRoundOneKey],
            proofBytesHex: generatedProof.proofBytesHex,
        });
        const verifyMilliseconds = Math.round(performance.now() - verifyStart);

        expect(verifiedProof.ok).toBe(true);
        expect(verifiedProof.proofFamily).toBe('trustee-evaluation-key');
        expect(verifiedProof.statementHash).toBe(generatedProof.statementHash);
        expect(verifiedProof.proofByteLength).toBe(
            generatedProof.proofByteLength,
        );

        const measurementRow = {
            measurementLane: 'desktop-chromium-browser-wasm',
            evidenceBoundary:
                'development desktop browser evidence; not supported-phone evidence',
            proofFamily: 'trustee-evaluation-key',
            measuredKey:
                'one relinearization round-one key at the selected working level',
            ringDegree: firstProfileRingDegree,
            rnsLimbCount: qSharePrimes.length,
            measuredKeyCount: generatedProof.keyCount,
            decompositionDigitCount,
            keySwitchLimbCount,
            componentSetupMilliseconds,
            proveMilliseconds,
            verifyMilliseconds,
            proofByteLength: generatedProof.proofByteLength,
            largestCopiedBufferBytes: proveRequestByteLength,
            largestCopiedBufferSource: 'serialized single-key prove request',
            peakWasmMemoryBytes: kernel.wasmMemoryByteLength(),
            persistentStorageBytes: 0,
            persistentStorageNote: 'the measurement lane persists nothing',
            resumeBehavior:
                'prove and verify are single kernel commands without partial state; an interrupted command restarts from its inputs',
            fullBatchBudgetNote:
                'the full per-trustee batch carries relinearization round one and round two plus the scheduled Galois rotations, all at this working level; its combined key-switch component witness materially exceeds single-shot JavaScript and WASM materialization, so mobile generation requires per-key streaming with chunk-bounded buffers rather than one batched request',
        };
        console.log(
            `trustee-evaluation-key-browser-measurement ${JSON.stringify(measurementRow)}`,
        );
        await commands.writeFile(
            'temp/browser-proof-benchmark/trustee-evaluation-key-measurement.json',
            `${JSON.stringify(measurementRow, null, 4)}\n`,
        );
    });
});
