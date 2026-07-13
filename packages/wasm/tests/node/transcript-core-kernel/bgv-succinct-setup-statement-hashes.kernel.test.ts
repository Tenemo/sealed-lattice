import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
// Shared hash vector set used by the Rust kernel test
// (trustee_evaluation_key_proof::tests): byte-identical succinct-setup statement
// hashes pinned across the TS/WASM and Rust provers. Edit the values in the JSON
// after an intended encoding change.
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

        const sourceConstantCommitments = qSharePrimes.map(
            (rnsPrime, rnsLimbIndex) =>
                zeroSetupCommitment(kernel, {
                    publicMatrixSeedHash,
                    sourceRnsLimbIndex: rnsLimbIndex,
                    sourceMessageModulus: rnsPrime,
                    shamirCoefficientIndex: 0,
                }).commitment,
        );
        const sameSecretBridgeMaterialSeedHex =
            '710a4433ff567caa099bd666df653f6a3bf44fcffca9c5daafa958984f8e45a68a7c8a6236586c90d7256e335025c785ff9658c7dfa5d7d608c70c98ccfee014';
        const sameSecretBridgeTarget =
            kernel.computeVssCommittedMaterialCommitment({
                commitmentRole: 'coefficient',
                commitmentContext: {
                    testPurpose: 'statement-vector-same-secret-bridge',
                },
                rnsLimbIndex: 0,
                rnsPrime: firstQSharePrime,
                ringDegree,
                messageCoefficientBound: firstQSharePrime,
                messageCoefficients: zeroU64Vector(),
                materialSeedHex: sameSecretBridgeMaterialSeedHex,
            });
        const sameSecret = kernel.generateSameSecretBridgeProof({
            context: {
                ceremonyId: 'statement-vector-ceremony',
                manifestHash: repeatedHash('10'),
                rosterHash: repeatedHash('20'),
                trusteeIdentity: 'statement-vector-trustee',
                trusteeRosterPosition: 0,
                setupEpoch: 'statement-vector-epoch',
            },
            ringDegree,
            sameSecretLinkage: {
                publicMatrixSeedHash,
                commitments: sourceConstantCommitments,
            },
            sameSecretBridge: {
                publicMatrixSeedHash,
                setupParametersHash: parameters.setupParametersHash,
                sourceTrusteeIdentity: 'statement-vector-trustee',
                sourceTrusteeRosterPosition: 0,
                bridgeRnsPrimes: [firstQSharePrime],
                targetConstantCommitmentRoots: [
                    sameSecretBridgeTarget.commitmentRoot,
                ],
                targetConstantCommitments: [sameSecretBridgeTarget.commitment],
            },
            secretCoefficients: zeroI64Vector(),
            negativeIndicatorCoefficients: zeroI64Vector(),
            openingRandomnessByLimb: Array.from(
                { length: qSharePrimes.length },
                () => zeroOpeningRandomness(),
            ),
            vssCommittedMaterialSeedsByBoundMessage: [
                sameSecretBridgeMaterialSeedHex,
            ],
            vssCommittedMaterialContextHashesByBoundMessage: [
                sameSecretBridgeTarget.commitmentContextHash,
            ],
            ...proofRandomnessFields,
        });
        expect(sameSecret.statementHash).toBe(
            expectedStatementHashes.sameSecret,
        );

        const publicKeyBridgeMaterialSeedHex =
            '192c6cd9305a6e29ce7d945665a223eed89e695463060689a89a15521638d91ae30efac6c283c07fe03869db777cf75b63c368f17568071a3dc4a0ef5bea6a68';
        const publicKeyBridgeTarget =
            kernel.computeVssCommittedMaterialCommitment({
                commitmentRole: 'coefficient',
                commitmentContext: {
                    testPurpose: 'statement-vector-public-key-bridge',
                },
                rnsLimbIndex: 0,
                rnsPrime: firstQSharePrime,
                ringDegree,
                messageCoefficientBound: firstQSharePrime,
                messageCoefficients: zeroU64Vector(),
                materialSeedHex: publicKeyBridgeMaterialSeedHex,
            });
        const publicKeyShare = kernel.generateTrusteeEvaluationKeyProof({
            context: statementContext({
                sameSecretBridgeStatementRoot: repeatedHash('31'),
                sameSecretBridgeProofRecordRoot: repeatedHash('32'),
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
            sameSecretBridge: {
                publicMatrixSeedHash: repeatedHash('41'),
                setupParametersHash: parameters.setupParametersHash,
                sourceTrusteeIdentity: 'statement-vector-trustee',
                sourceTrusteeRosterPosition: 0,
                bridgeRnsPrimes: [firstQSharePrime],
                targetConstantCommitmentRoots: [
                    publicKeyBridgeTarget.commitmentRoot,
                ],
                targetConstantCommitments: [publicKeyBridgeTarget.commitment],
            },
            secretCoefficients: zeroI64Vector(),
            errorCoefficientsByKey: [[zeroI64Vector()]],
            negativeIndicatorCoefficients: zeroI64Vector(),
            vssCommittedMaterialSeedsByBoundMessage: [
                publicKeyBridgeMaterialSeedHex,
            ],
            vssCommittedMaterialContextHashesByBoundMessage: [
                publicKeyBridgeTarget.commitmentContextHash,
            ],
            ...proofRandomnessFields,
        });
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

        // The key-bearing statement links its atom secret directly to the
        // canonical source constant commitment. The describe command pins the
        // same parsed statement hash as the Rust vector without running the
        // heavy prover in this fast vector lane.
        const trusteeEvaluationKeyPublicMatrixSeedHash = repeatedHash('43');
        const trusteeEvaluationKeySourceCommitment = zeroSetupCommitment(
            kernel,
            {
                publicMatrixSeedHash: trusteeEvaluationKeyPublicMatrixSeedHash,
                sourceRnsLimbIndex: 0,
                sourceMessageModulus: firstQSharePrime,
                shamirCoefficientIndex: 0,
            },
        ).commitment;
        const trusteeEvaluationKey =
            kernel.describeTrusteeEvaluationKeyStatement({
                context: statementContext({
                    requiredGaloisSetHash: repeatedHash('33'),
                    evaluatorKeyScheduleRoot: repeatedHash('34'),
                    sourceConstantCoefficientCommitmentRoot: repeatedHash('36'),
                }),
                ringDegree,
                keys: [
                    {
                        proofFamily: 'relinearization-round-one',
                        level: 2,
                        keySwitchDomain: 'relinearization-round-one',
                        keySwitchSeedHex: repeatedHash('42'),
                        componentBByDigit: [
                            [zeroU64Vector(), zeroU64Vector(), zeroU64Vector()],
                            [zeroU64Vector(), zeroU64Vector(), zeroU64Vector()],
                            [zeroU64Vector(), zeroU64Vector(), zeroU64Vector()],
                        ],
                    },
                ],
                sameSecretLinkage: {
                    publicMatrixSeedHash:
                        trusteeEvaluationKeyPublicMatrixSeedHash,
                    commitments: [trusteeEvaluationKeySourceCommitment],
                },
            });
        expect(trusteeEvaluationKey.statementHash).toBe(
            expectedStatementHashes.trusteeEvaluationKey,
        );
    });
});
