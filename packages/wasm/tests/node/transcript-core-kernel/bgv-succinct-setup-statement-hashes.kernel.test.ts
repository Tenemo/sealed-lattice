import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvCollectiveSetupProfileDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

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

// These vectors are the same constants asserted in the Rust kernel tests; they pin canonical statement-hash agreement across the TS/WASM and Rust provers, so a mismatch means a cross-implementation encoding drift, not a fixture refresh.
const expectedStatementHashes = {
    sameSecret:
        'c300200cb9bde4e95f2129ad4c07ca6fa22a2c236278be5f0be474095f604d3afd0613c791e807dc4e4d942f202ea4f5cac20d5a93745eab3d87abf05a3cf4ee',
    publicKeyShare:
        '108d59c7677c2007c43910828650f4a93d7555c63041e5865dcc906ca3b6e114456c85fc963165929bc676aac063307b69ecc18c3abcfa6f0f91a6bbcdff861e',
    privateVssShare:
        'fe6c24a4c3d7d021ca34da3d02e7820a64872831a6e641197c613151dd77c3ee64113e1c1dfc5c9af354e538ad3ffa4c73db6978346b26a303b4283a845f9be8',
    trusteeEvaluationKey:
        '11fce9a48c01d57c8b08e2816a9a7704623775fcfdf5afca029ec4d2c32f5c2f070e567c2042e6554f6bbb3f46fe75a4711b8b52ab6626509e0ecd10f307bef0',
} as const;

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
    proofRandomnessSource: 'development-deterministic-fixture',
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
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord => ({
    ceremonyId: 'statement-vector-ceremony',
    manifestHash: repeatedHash('10'),
    rosterHash: repeatedHash('20'),
    setupProfileHash: profile.setupProfileHash,
    qShareHash: profile.qShareHash,
    carryAwareVssShareRelationProfileHash:
        profile.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: profile.commitmentProfileHash,
    setupEpoch: 'statement-vector-epoch',
});

const privateVssRequest = (
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): PrivateVssProofInput => {
    const currentSetupContext = setupContext(profile);
    const publicMatrixSeedHash = repeatedHash('40');
    const coefficientCommitments: JsonRecord[] = [];
    const materialRecords: JsonRecord[] = [];
    const coefficientCommitmentRoots: string[] = [];
    const firstQSharePrime = profile.qShare.primes[0];
    if (firstQSharePrime === undefined) {
        throw new Error(
            'Collective setup profile must include Q_share primes.',
        );
    }

    profile.qShare.primes.forEach((rnsPrime, rnsLimbIndex) => {
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
                setupProfileHash: currentSetupContext.setupProfileHash,
                qShareHash: currentSetupContext.qShareHash,
                carryAwareVssShareRelationProfileHash:
                    currentSetupContext.carryAwareVssShareRelationProfileHash,
                commitmentProfileHash:
                    currentSetupContext.commitmentProfileHash,
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
                setupProfileHash: currentSetupContext.setupProfileHash,
                qShareHash: currentSetupContext.qShareHash,
                carryAwareVssShareRelationProfileHash:
                    currentSetupContext.carryAwareVssShareRelationProfileHash,
                commitmentProfileHash:
                    currentSetupContext.commitmentProfileHash,
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
        setupProfileHash: currentSetupContext.setupProfileHash,
        qShareHash: currentSetupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            currentSetupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: currentSetupContext.commitmentProfileHash,
        setupEpoch: 'statement-vector-epoch',
        sourceTrusteeIdentity: 'statement-vector-trustee',
        sourceTrusteeRosterPosition: 0,
        publicMatrixSeedHash,
        coefficientCommitments,
    };
    sourceTrusteeRecord.sourceTrusteeCommitmentRoot = kernel.deriveProtocolHash(
        {
            namespace: 'VssCoefficientCommitmentRoot',
            value: sourceTrusteeRecord,
        },
    );

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
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const publicMatrixSeedHash = repeatedHash('40');
        const qSharePrimes = profile.qShare.primes;
        const firstQSharePrime = qSharePrimes[0];
        if (firstQSharePrime === undefined) {
            throw new Error(
                'Collective setup profile must include Q_share primes.',
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
            privateVssRequest(kernel, profile),
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
