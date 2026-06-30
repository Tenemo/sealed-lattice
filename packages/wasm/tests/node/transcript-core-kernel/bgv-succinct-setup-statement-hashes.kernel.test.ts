import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
// Single source of truth shared with the Rust kernel test
// (trustee_evaluation_key_proof::tests): byte-identical succinct-setup statement
// hashes pinned across the TS/WASM and Rust provers. Edit the values in the JSON
// and run `pnpm run vectors:generate` after an intended encoding change.
import expectedStatementHashes from '#test-vectors/succinct-setup-statement-hashes.json';

type JsonRecord = Record<string, unknown>;
type TrusteeProofInput = Parameters<
    TranscriptCoreKernel['generateTrusteeEvaluationKeyProof']
>[0];
type TrusteeStatementContext = TrusteeProofInput['context'];
type PrivateVssProofInput = Parameters<
    TranscriptCoreKernel['generatePrivateVssShareProof']
>[0];

const ringDegree = 128;
const proofRandomnessSeedHex =
    '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const proofRandomnessNonceHex =
    'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

const repeatedHash = (bytePair: string): string => bytePair.repeat(64);

const zeroU64Vector = (): number[] =>
    Array.from({ length: ringDegree }, () => 0);

const zeroI64Vector = (): number[] =>
    Array.from({ length: ringDegree }, () => 0);

const zeroOpeningRandomness = (): readonly number[][] =>
    Array.from({ length: 5 }, () => zeroI64Vector());

const statementContext = (bindingRoots: JsonRecord): TrusteeStatementContext =>
    ({
        ceremonyId: 'statement-vector-ceremony',
        manifestHash: repeatedHash('10'),
        rosterHash: repeatedHash('20'),
        trusteeIdentity: 'statement-vector-trustee',
        trusteeRosterPosition: 0,
        setupEpoch: 'statement-vector-epoch',
        ...bindingRoots,
    }) as TrusteeStatementContext;

const proofRandomnessFields = {
    proofRandomnessSeedHex,
    proofRandomnessNonceHex,
} as const;

const zeroSetupCommitment = (
    kernel: TranscriptCoreKernel,
    input: {
        readonly publicMatrixSeedHash: string;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
    },
): {
    readonly commitment: JsonRecord;
    readonly commitmentRoot: string;
} => {
    const computation = kernel.computeSetupCommitmentFromOpening({
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceRnsLimbIndex: input.sourceRnsLimbIndex,
        sourceMessageModulus: input.sourceMessageModulus,
        shamirCoefficientIndex: input.shamirCoefficientIndex,
        messageCoefficients: zeroU64Vector(),
        randomnessByColumn: zeroOpeningRandomness(),
        ringDegree,
    });

    return {
        commitment: computation.commitment,
        commitmentRoot: computation.commitmentRoot,
    };
};

const setupContext = (
    parameters: BgvCollectiveSetupParametersDescription,
): JsonRecord => ({
    ceremonyId: 'statement-vector-ceremony',
    manifestHash: repeatedHash('10'),
    rosterHash: repeatedHash('20'),
    setupParametersHash: parameters.setupParametersHash,
    setupEpoch: 'statement-vector-epoch',
});

const privateVssRequest = (
    kernel: TranscriptCoreKernel,
    parameters: BgvCollectiveSetupParametersDescription,
): PrivateVssProofInput => {
    const currentSetupContext = setupContext(parameters);
    const publicMatrixSeedHash = repeatedHash('40');
    const coefficientCommitments: JsonRecord[] = [];
    const materialRecords: JsonRecord[] = [];
    const coefficientCommitmentRoots: string[] = [];
    const firstQSharePrime = parameters.qShare.primes[0];
    if (firstQSharePrime === undefined) {
        throw new Error(
            'Collective setup parameters must include Q_share primes.',
        );
    }

    parameters.qShare.primes.forEach((rnsPrime, rnsLimbIndex) => {
        Array.from({ length: 4 }, (_unused, shamirCoefficientIndex) => {
            const { commitment, commitmentRoot } = zeroSetupCommitment(kernel, {
                publicMatrixSeedHash,
                sourceRnsLimbIndex: rnsLimbIndex,
                sourceMessageModulus: rnsPrime,
                shamirCoefficientIndex,
            });
            if (rnsLimbIndex === 0) {
                coefficientCommitmentRoots.push(commitmentRoot);
            }
            coefficientCommitments.push({
                objectType: 'VssCoefficientCommitment',
                objectVersion: 1,
                ceremonyId: 'statement-vector-ceremony',
                manifestHash: repeatedHash('10'),
                rosterHash: repeatedHash('20'),
                setupParametersHash: currentSetupContext.setupParametersHash,
                setupEpoch: 'statement-vector-epoch',
                sourceTrusteeIdentity: 'statement-vector-trustee',
                sourceTrusteeRosterPosition: 0,
                publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex,
                commitmentRoot,
            });
            materialRecords.push({
                objectType: 'VssCoefficientCommitmentMaterial',
                objectVersion: 1,
                ceremonyId: 'statement-vector-ceremony',
                manifestHash: repeatedHash('10'),
                rosterHash: repeatedHash('20'),
                setupParametersHash: currentSetupContext.setupParametersHash,
                setupEpoch: 'statement-vector-epoch',
                sourceTrusteeIdentity: 'statement-vector-trustee',
                sourceTrusteeRosterPosition: 0,
                publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex,
                commitmentRoot,
                commitment,
            });
        });
    });

    const sourceTrusteeRecord: JsonRecord = {
        objectType: 'VssSourceTrusteeCoefficientCommitments',
        objectVersion: 1,
        ceremonyId: 'statement-vector-ceremony',
        manifestHash: repeatedHash('10'),
        rosterHash: repeatedHash('20'),
        setupParametersHash: currentSetupContext.setupParametersHash,
        setupEpoch: 'statement-vector-epoch',
        sourceTrusteeIdentity: 'statement-vector-trustee',
        sourceTrusteeRosterPosition: 0,
        publicMatrixSeedHash,
        coefficientCommitments,
    };
    sourceTrusteeRecord.sourceTrusteeCommitmentRoot =
        kernel.deriveCanonicalObjectHash({
            value: sourceTrusteeRecord,
        });

    return {
        setupContext: currentSetupContext,
        publicMatrixSeedHash,
        privateEnvelopeAadHash: repeatedHash('44'),
        sourceTrusteeCoefficientCommitmentRecord: sourceTrusteeRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords: materialRecords,
        recipientIdentity: 'statement-vector-recipient',
        recipientRosterPosition: 2,
        rnsLimbIndex: 0,
        rnsPrime: firstQSharePrime,
        ringDegree,
        shareValues: zeroU64Vector(),
        coefficientCommitmentRoots,
        coefficientMessagesByShamirIndex: Array.from({ length: 4 }, () =>
            zeroU64Vector(),
        ),
        openingRandomnessByShamirIndex: Array.from({ length: 4 }, () =>
            Array.from({ length: 5 }, () => zeroI64Vector()),
        ),
        ...proofRandomnessFields,
    };
};

describe('succinct setup statement hash vectors', () => {
    it('matches Rust native vectors for every current setup proof family', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const publicMatrixSeedHash = repeatedHash('40');
        const qSharePrimes = parameters.qShare.primes;
        const firstQSharePrime = qSharePrimes[0];
        if (firstQSharePrime === undefined) {
            throw new Error(
                'Collective setup parameters must include Q_share primes.',
            );
        }

        const sameSecretCommitments = qSharePrimes.map(
            (rnsPrime, rnsLimbIndex) =>
                zeroSetupCommitment(kernel, {
                    publicMatrixSeedHash,
                    sourceRnsLimbIndex: rnsLimbIndex,
                    sourceMessageModulus: rnsPrime,
                    shamirCoefficientIndex: 0,
                }).commitment,
        );
        const sameSecret = kernel.generateTrusteeEvaluationKeyProof({
            context: statementContext({
                vssCoefficientCommitmentMaterialRoot: repeatedHash('30'),
            }),
            ringDegree,
            keys: [],
            sameSecretLinkage: {
                publicMatrixSeedHash,
                commitments: sameSecretCommitments,
            },
            secretCoefficients: zeroI64Vector(),
            errorCoefficientsByKey: [],
            negativeIndicatorCoefficients: zeroI64Vector(),
            openingRandomnessByLimb: Array.from(
                { length: qSharePrimes.length },
                () => zeroOpeningRandomness(),
            ),
            ...proofRandomnessFields,
        });
        expect(sameSecret.proofFamily).toBe('same-secret-linkage-anchor');
        expect(sameSecret.statementHash).toBe(
            expectedStatementHashes.sameSecret,
        );

        const publicKeyLinkageCommitment = zeroSetupCommitment(kernel, {
            publicMatrixSeedHash: repeatedHash('41'),
            sourceRnsLimbIndex: 0,
            sourceMessageModulus: firstQSharePrime,
            shamirCoefficientIndex: 0,
        }).commitment;
        const publicKeyShare = kernel.generateTrusteeEvaluationKeyProof({
            context: statementContext({
                sameSecretStatementRoot: repeatedHash('31'),
                sameSecretProofRoot: repeatedHash('32'),
            }),
            ringDegree,
            keys: [
                {
                    proofFamily: 'public-key-share',
                    level: qSharePrimes.length - 1,
                    keySwitchDomain: 'accepted-bgv-public-a',
                    keySwitchSeedHex: repeatedHash('41'),
                    componentBByDigit: [
                        qSharePrimes.map(() => zeroU64Vector()),
                    ],
                },
            ],
            sameSecretLinkage: {
                publicMatrixSeedHash: repeatedHash('41'),
                commitments: [publicKeyLinkageCommitment],
            },
            secretCoefficients: zeroI64Vector(),
            errorCoefficientsByKey: [[zeroI64Vector()]],
            negativeIndicatorCoefficients: zeroI64Vector(),
            openingRandomnessByLimb: [zeroOpeningRandomness()],
            ...proofRandomnessFields,
        });
        expect(publicKeyShare.proofFamily).toBe('public-key-share');
        expect(publicKeyShare.statementHash).toBe(
            expectedStatementHashes.publicKeyShare,
        );

        const privateVssShare = kernel.generatePrivateVssShareProof(
            privateVssRequest(kernel, parameters),
        );
        expect(privateVssShare.privateVssShareProof.proofFamily).toBe(
            'vss-opening-carry',
        );
        expect(privateVssShare.privateVssShareProof.statementHash).toBe(
            expectedStatementHashes.privateVssShare,
        );

        const trusteeEvaluationKey = kernel.generateTrusteeEvaluationKeyProof({
            context: statementContext({
                requiredGaloisSetHash: repeatedHash('33'),
                evaluatorKeyScheduleRoot: repeatedHash('34'),
                keySwitchDecompositionHash: repeatedHash('35'),
                sameSecretStatementRoot: repeatedHash('36'),
                sameSecretProofRoot: repeatedHash('37'),
            }),
            ringDegree,
            keys: [
                {
                    proofFamily: 'relinearization-round-one',
                    level: 0,
                    keySwitchDomain: 'relinearization-round-one',
                    keySwitchSeedHex: repeatedHash('42'),
                    componentBByDigit: [[zeroU64Vector()]],
                },
            ],
            secretCoefficients: zeroI64Vector(),
            errorCoefficientsByKey: [[zeroI64Vector()]],
            ...proofRandomnessFields,
        });
        expect(trusteeEvaluationKey.proofFamily).toBe('trustee-evaluation-key');
        expect(trusteeEvaluationKey.statementHash).toBe(
            expectedStatementHashes.trusteeEvaluationKey,
        );
    });
});
