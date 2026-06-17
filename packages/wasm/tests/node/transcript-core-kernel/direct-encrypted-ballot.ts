import type {
    CanonicalSignedRootObject,
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import { deriveProtocolHash, hash512Hex } from '#packages/crypto/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';
import type {
    BgvAcceptedSetupHandoff,
    BgvPassiveSetupPackage,
    DirectBallotAcceptedPublicKeyMaterial,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
} from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';
import {
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    runKernelCommand,
} from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';

const wasmKernelUrl = new URL(
    '../../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export const directBallotSetupSeed = 'direct-encrypted-ballot-node-wasm-seed';

const textEncoder = new TextEncoder();
const publicKeyShareCoefficientVectorHashDomain =
    'sealed-lattice-bgv-rns/public-key-share-coefficient-vector-v1';

const hexToBytes = (hexValue: string): Uint8Array => {
    if (hexValue.length % 2 !== 0 || /[^0-9a-f]/u.test(hexValue)) {
        throw new Error('hex value must be lowercase and byte-aligned.');
    }

    return Uint8Array.from(
        { length: hexValue.length / 2 },
        (_unusedByte, byteIndex) =>
            Number.parseInt(
                hexValue.slice(byteIndex * 2, byteIndex * 2 + 2),
                16,
            ),
    );
};

const createFreshRandomnessHex = (): string => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Proof generation requires Web Crypto getRandomValues for fresh randomness.',
        );
    }
    const randomBytes = new Uint8Array(32);
    cryptoProvider.getRandomValues(randomBytes);

    return Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');
};

const suppliedOrFreshRandomnessHex = (value: string | undefined): string =>
    value ?? createFreshRandomnessHex();

export const directBallotScores = [
    10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
] as const;

export type DirectEncryptedBallotEvaluatorReplayResult = {
    readonly topCount: number;
    readonly scoreDomainMax: number;
    readonly tiePolicy: string;
    readonly workingLevel: number;
    readonly evaluationKeyMaterialSource: string;
    readonly publicEvaluationKeyMaterialHash?: string;
    readonly packedScoreRoot: string;
    readonly rankRoot: string;
    readonly targetProjection: string;
    readonly targetLayoutHash: string;
    readonly targetIdRoot: string;
    readonly targetOrderRoot: string;
    readonly targetCiphertextHash: string;
    readonly evaluatorReplayContextHash: string;
    readonly evaluatorReplayRecordHash: string;
    readonly targetProposal:
        | {
              readonly status: string;
              readonly requiredForFinality: string;
          }
        | {
              readonly targetProposalHash: string;
              readonly ceremonyId: string;
              readonly electionManifestHash: string;
              readonly thresholdProfileHash: string;
              readonly evaluatorReplayContextHash: string;
              readonly evaluatorReplayRecordHash: string;
              readonly encryptedBallotAggregateHash: string;
              readonly targetCiphertextHash: string;
              readonly targetLayoutHash: string;
              readonly evaluatorReplayProfileHash: string;
              readonly targetFinalityPolicyHash: string;
          };
    readonly privateCorrectnessCheck: string;
    readonly timingStatus: string;
    readonly replayTimeMilliseconds: string;
};

export type DirectEncryptedBallotProofChunkManifest = {
    readonly objectType: 'BallotProofChunkManifest';
    readonly objectVersion: 1;
    readonly proofByteLength: number;
    readonly chunkSizeBytes: number;
    readonly chunkCount: number;
    readonly chunkHashList: readonly string[];
    readonly chunkMerkleRoot: string;
    readonly proofFullBytesHash: string;
    readonly statementHash: string;
    readonly ciphertextRoot: string;
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
    readonly actionContextHash: string;
    readonly setupPackageRoot: string;
    readonly proofProfileHash: string;
};

export type DirectEncryptedBallotCiphertextLimbRoot = {
    readonly componentIndex: number;
    readonly limbIndex: number;
    readonly modulus: number;
    readonly limbRoot: string;
};

export type DirectEncryptedBallotCiphertextTransport = {
    readonly encoding: 'sealed-lattice-bgv-rns-canonical-ciphertext-v1';
    readonly canonicalByteLength: number;
    readonly canonicalBytesHex: string;
    readonly ciphertextRoot: string;
    readonly ciphertextLimbRoots: readonly DirectEncryptedBallotCiphertextLimbRoot[];
};

export type DirectEncryptedBallotPackage = {
    readonly objectType: 'EncryptedBallotPackage';
    readonly objectVersion: 1;
    readonly ceremonyId: string;
    readonly manifestHash: string;
    readonly rosterHash: string;
    readonly thresholdProfileHash: string;
    readonly setupPackageRoot: string;
    readonly setupProfileHash: string;
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
    readonly actionContextHash: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly bgvProfileHash: string;
    readonly batchEncoderHash: string;
    readonly batchLayoutBindingHash: string;
    readonly ballotScoreEncodingProfileHash: string;
    readonly encryptedBallotLayoutHash: string;
    readonly directBallotReservedSlotRuleHash: string;
    readonly directBallotEncoderMatrixRoot: string;
    readonly witnessPartitionProfileHash: string;
    readonly arithmeticCertificateHash: string;
    readonly soundnessCertificateHash: string;
    readonly zeroKnowledgeCertificateHash: string;
    readonly verifierCertificateHash: string;
    readonly collectivePublicKeyRoot: string;
    readonly bgvPublicKeyRoot: string;
    readonly ciphertextRoot: string;
    readonly ciphertextTransport: DirectEncryptedBallotCiphertextTransport;
    readonly proofProfileHash: string;
    readonly proofStatementHash: string;
    readonly proofChunkManifest: DirectEncryptedBallotProofChunkManifest;
    readonly proofFullBytesHash: string;
    readonly proofChunkRoot: string;
    readonly packageRoot: string;
    readonly signature: ProtocolSignatureEnvelope | null;
};

export type DirectEncryptedBallotProofChunk = {
    readonly chunkIndex: number;
    readonly byteLength: number;
    readonly chunkHash: string;
    readonly bytesHex: string;
};

export type DirectEncryptedBallotResult = {
    readonly operation: 'runDirectEncryptedBallot';
    readonly profile: {
        readonly dataPrimeCount: number;
    };
    readonly ballotLayout: {
        readonly optionCount: number;
    };
    readonly input: {
        readonly ballotCount: number;
    };
    readonly encryptedBallots: {
        readonly ballotEncryptionRandomness: {
            readonly source:
                | 'fresh-csprng'
                | 'development-deterministic-fixture';
            readonly ballotEncryptionRandomnessCount: number;
            readonly randomnessBytesPerBallot: number;
            readonly retention: string;
            readonly sourceStatement: string;
        };
    };
    readonly proofAttempt: {
        readonly coverage: string;
        readonly proofCount: number;
        readonly rnsLimbCount: number;
        readonly responseEncoding: string;
        readonly bgvCommitmentEncoding: string;
        readonly projectedBgvRelationProjectionsPerLimbComponent: number;
        readonly responsePolynomialDegree: number;
        readonly sharedResponsePolynomialCount: number;
        readonly proofSizeBytes: number;
        readonly verifiedProofSizeBytes: number;
        readonly totalProofBytes: number;
        readonly proofBytesHash: string;
        readonly proofGate: string;
        readonly timingStatus: string;
        readonly challengeSoundness: string;
        readonly proofAccounting: {
            readonly soundnessCertificateHash: string;
            readonly zeroKnowledgeCertificateHash: string;
            readonly verifierCertificateHash: string;
            readonly challengeBits: number;
            readonly nominalChallengeBits: number;
            readonly proofModelAccepted: boolean;
            readonly projectedBgvRelationProjectionsPerLimbComponent: number;
            readonly projectedBgvRelationCommitmentScalars: number;
            readonly projectedBgvNoWrapCarryResponseScalars: number;
            readonly weakestCheckedRelation: string;
            readonly weakestRelationEffectiveBitsPerCheck: number;
            readonly committedTraceSoundness: unknown;
            readonly outerResponseZeroKnowledge: unknown;
            readonly committedTraceZeroKnowledge: unknown;
            readonly effectiveStatisticalZeroKnowledgeBits: number;
            readonly committedTraceSupportRows: string;
            readonly classicalSoundnessBitsAfterCommittedTraceAccounting: number;
            readonly maskCoefficientBits: number;
            readonly responseCoefficientBytes: number;
            readonly projectedBgvNoWrapCarryResponseBytes: number;
            readonly targetClassicalSoundnessBits: number;
            readonly minimumIndependentRepetitionsForTarget: number;
            readonly minimumIndependentRepetitionsStatus: string;
            readonly estimatedIndependentRepetitionsFromWeakestRelationBeforeUnionLosses: number;
            readonly estimatedRepeatedProofSizeBytes: number;
            readonly estimatedRepeatedTotalProofBytes: number;
            readonly witnessBoundBitsForMaskShiftAccounting: number;
            readonly zeroKnowledgeShiftSlackBitsAfterResponseUnionBound: number;
            readonly decision: string;
        };
        readonly proofTransport: {
            readonly encoding: string;
            readonly status: string;
            readonly retention: string;
            readonly chunkSizeBytes: number;
            readonly chunksPerProof: number;
            readonly chunksForBatch: number;
            readonly transportedProofSizeBytes: number;
            readonly transportedProofBytesHash: string;
            readonly firstProofChunkMerkleRoot: string;
            readonly firstProofChunkHashes: readonly string[];
            readonly firstProofChunkManifestRoot: string;
            readonly firstProofChunkManifest: DirectEncryptedBallotProofChunkManifest;
            readonly firstEncryptedBallotPackageRoot: string;
            readonly firstEncryptedBallotPackage: DirectEncryptedBallotPackage;
            readonly firstVoterSignatureSignedRoot: CanonicalSignedRootObject;
            readonly firstProofStatementHash: string;
            readonly proofProfileHash: string;
            readonly arithmeticCertificateHash: string;
            readonly soundnessCertificateHash: string;
            readonly zeroKnowledgeCertificateHash: string;
            readonly verifierCertificateHash: string;
        };
        readonly proofMaskRandomness: {
            readonly source:
                | 'fresh-csprng'
                | 'development-deterministic-fixture';
            readonly ballotProofRandomnessCount: number;
            readonly randomnessBytesPerProof: number;
            readonly retention: string;
            readonly sourceStatement: string;
        };
    };
    readonly aggregation: {
        readonly ballotCount: number;
        readonly aggregateCiphertextRoot: string;
        readonly aggregateCiphertextCanonicalByteLength: number;
        readonly privateCorrectnessCheck: string;
        readonly result: string;
    };
    readonly evaluatorReplay:
        | string
        | DirectEncryptedBallotEvaluatorReplayResult
        | readonly DirectEncryptedBallotEvaluatorReplayResult[];
};

export type DirectEncryptedBallotPackageCreationResult = {
    readonly operation: 'createDirectEncryptedBallotPackages';
    readonly profile: DirectEncryptedBallotResult['profile'];
    readonly ballotLayout: DirectEncryptedBallotResult['ballotLayout'];
    readonly input: DirectEncryptedBallotResult['input'];
    readonly encryptedBallots: DirectEncryptedBallotResult['encryptedBallots'];
    readonly encryptedBallotPackages: readonly {
        readonly ballotIndex: number;
        readonly voterIdentity: string;
        readonly voterRosterPosition: number;
        readonly actionContextHash: string;
        readonly encryptedBallotHash: string;
        readonly ciphertextRoot: string;
        readonly ciphertextCanonicalByteLength: number;
        readonly statementHash: string;
        readonly proofBytesHash: string;
        readonly proofChunkManifestRoot: string;
        readonly encryptedBallotPackageRoot: string;
        readonly proofChunkManifest: DirectEncryptedBallotProofChunkManifest;
        readonly proofChunks: readonly DirectEncryptedBallotProofChunk[];
        readonly encryptedBallotPackage: DirectEncryptedBallotPackage;
        readonly voterSignatureSignedRoot: CanonicalSignedRootObject;
    }[];
    readonly packageCreation: {
        readonly setupHandoffRoot: string;
        readonly setupBoundary: string;
        readonly witnessBoundary: string;
        readonly proofBytesRetention: string;
        readonly signatureBoundary: string;
        readonly claimBoundary: string;
    };
    readonly proofAttempt: DirectEncryptedBallotResult['proofAttempt'];
    readonly decision: string;
};

export type DirectEncryptedBallotPackageVerificationResult = {
    readonly operation: 'verifyDirectEncryptedBallotPackage';
    readonly verificationStatus: string;
    readonly acceptedSetupHandoffRoot: string;
    readonly packageRoot: string;
    readonly ciphertextRoot: string;
    readonly proofStatementHash: string;
    readonly verifiedStatementHash: string;
    readonly proofBytesHash: string;
    readonly proofChunkRoot: string;
    readonly proofSizeBytes: number;
    readonly proofChunkCount: number;
    readonly relationCommitmentHash: string;
    readonly challenge: string;
    readonly signatureHash: string;
    readonly packageVerificationCertificateHash: ProtocolHash;
    readonly packageVerificationCertificate: DirectEncryptedBallotPackageVerificationCertificate;
    readonly signatureStatus: string;
    readonly claimBoundary: string;
};

export type DirectEncryptedBallotPackageVerificationCertificate = {
    readonly objectType: 'DirectEncryptedBallotPackageVerificationCertificate';
    readonly objectVersion: 1;
    readonly verification: string;
    readonly claimBoundary: string;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly thresholdProfileHash: ProtocolHash;
    readonly acceptedSetupHandoffRoot: ProtocolHash;
    readonly setupPackageRoot: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
    readonly voterSigningPublicKeyHash: ProtocolHash;
    readonly signatureHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly packageRoot: ProtocolHash;
    readonly ciphertextRoot: ProtocolHash;
    readonly ciphertextCanonicalByteLength: number;
    readonly proofStatementHash: ProtocolHash;
    readonly verifiedStatementHash: ProtocolHash;
    readonly proofProfileHash: ProtocolHash;
    readonly arithmeticCertificateHash: ProtocolHash;
    readonly soundnessCertificateHash: ProtocolHash;
    readonly zeroKnowledgeCertificateHash: ProtocolHash;
    readonly verifierCertificateHash: ProtocolHash;
    readonly proofFullBytesHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkCount: number;
    readonly proofChunkSizeBytes: number;
    readonly proofSizeBytes: number;
    readonly relationCommitmentHash: ProtocolHash;
    readonly challenge: string;
    readonly publicAggregationInput: {
        readonly packageRoot: ProtocolHash;
        readonly ciphertextRoot: ProtocolHash;
        readonly proofStatementHash: ProtocolHash;
        readonly proofChunkRoot: ProtocolHash;
        readonly acceptedSetupHandoffRoot: ProtocolHash;
        readonly setupPackageRoot: ProtocolHash;
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly bgvPublicKeyRoot: ProtocolHash;
        readonly proofProfileHash: ProtocolHash;
        readonly arithmeticCertificateHash: ProtocolHash;
        readonly soundnessCertificateHash: ProtocolHash;
        readonly zeroKnowledgeCertificateHash: ProtocolHash;
        readonly verifierCertificateHash: ProtocolHash;
    };
    readonly packageVerificationCertificateHash: ProtocolHash;
};

export const createDirectBallotSetupPackage = (
    kernel: TranscriptCoreKernel,
): BgvPassiveSetupPackage =>
    kernel.generateBgvPassiveSetup({
        ceremonyId: 'direct-encrypted-ballot-node-wasm-ceremony',
        manifestHash: deriveProtocolHash('ElectionManifestHash', {
            manifest: 'direct encrypted ballot node wasm smoke',
        }),
        rosterHash: deriveProtocolHash('RosterHash', {
            roster: 'direct encrypted ballot node wasm smoke',
        }),
        thresholdProfileHash: deriveProtocolHash('ThresholdProfileHash', {
            threshold: 'direct encrypted ballot node wasm smoke',
        }),
        participants: [
            {
                trusteeIdentity: 'trustee-1',
                rosterPosition: 0,
                boardPosition: 0,
            },
            {
                trusteeIdentity: 'trustee-2',
                rosterPosition: 1,
                boardPosition: 1,
            },
            {
                trusteeIdentity: 'trustee-3',
                rosterPosition: 2,
                boardPosition: 2,
            },
        ],
        setupSeed: directBallotSetupSeed,
    });

function directBallotWitnessPartitionProfileHash(
    kernel: TranscriptCoreKernel,
    profile: ReturnType<TranscriptCoreKernel['describeBgvRnsProfile']>,
): string {
    return kernel.deriveProtocolHash({
        namespace: 'DirectBallotWitnessPartitionProfileHash',
        value: {
            objectType: 'DirectBallotWitnessPartitionProfile',
            objectVersion: 1,
            statementId: 'BallotValidityStatement-v1',
            proofProfileId: 'direct-encrypted-ballot-validity-relation-v1',
            sourceRingDegree: profile.profile.polynomialDegree,
            plaintextModulus: profile.profile.plaintextModulus,
            dataPrimeCount: profile.profile.dataPrimes.length,
            optionCount: 20,
            scoreBucketCount: 10,
            responseEncodingOrder: [
                'randomizerPolynomial',
                'firstErrorPolynomial',
                'secondErrorPolynomial',
                'encodingCarryPolynomial',
                'scoreScalars',
                'oneHotBucketScalarsByOption',
                'projectedBgvNoWrapCarryScalars',
            ],
            privateWitnessPartitions: [
                {
                    partitionId: 'scoreScalars',
                    valueKind: 'bounded integer scalar per option',
                    scalarCount: 20,
                    minimum: 1,
                    maximum: 10,
                    responseOrder: 4,
                    maskDomain:
                        'sealed-lattice/direct-encrypted-ballot/relation-mask-scalar-v1',
                    maskVectorIndex: 4,
                    packageRetention: 'not retained',
                },
                {
                    partitionId: 'oneHotBucketScalarsByOption',
                    valueKind:
                        'one-hot score bucket scalar per option and bucket',
                    rowCount: 20,
                    columnCount: 10,
                    entrySet: [0, 1],
                    rowSum: 1,
                    responseOrder: 5,
                    maskDomain:
                        'sealed-lattice/direct-encrypted-ballot/relation-mask-scalar-v1',
                    firstMaskVectorIndex: 5,
                    packageRetention: 'not retained',
                },
                {
                    partitionId: 'encodedPlaintextPolynomial',
                    valueKind: 'batch-encoded score polynomial',
                    coefficientCount: profile.profile.polynomialDegree,
                    source: 'Encode_p(score slots, reserved zero slots, batch encoder profile)',
                    constraint:
                        'linked to scoreScalars through encodingCarryPolynomial',
                    responseOrder: 'derived, not separately encoded',
                    packageRetention: 'not retained',
                },
                {
                    partitionId: 'randomizerPolynomial',
                    valueKind: 'signed integer polynomial',
                    coefficientCount: profile.profile.polynomialDegree,
                    support: 'ternary {-1,0,1}',
                    responseOrder: 0,
                    maskDomain:
                        'sealed-lattice/direct-encrypted-ballot/relation-mask-v1',
                    maskVectorIndex: 0,
                    packageRetention: 'not retained',
                },
                {
                    partitionId: 'firstErrorPolynomial',
                    valueKind: 'signed integer polynomial',
                    coefficientCount: profile.profile.polynomialDegree,
                    support: 'centered binomial eta-2 range [-2,2]',
                    responseOrder: 1,
                    maskDomain:
                        'sealed-lattice/direct-encrypted-ballot/relation-mask-v1',
                    maskVectorIndex: 1,
                    packageRetention: 'not retained',
                },
                {
                    partitionId: 'secondErrorPolynomial',
                    valueKind: 'signed integer polynomial',
                    coefficientCount: profile.profile.polynomialDegree,
                    support: 'centered binomial eta-2 range [-2,2]',
                    responseOrder: 2,
                    maskDomain:
                        'sealed-lattice/direct-encrypted-ballot/relation-mask-v1',
                    maskVectorIndex: 2,
                    packageRetention: 'not retained',
                },
                {
                    partitionId: 'encodingCarryPolynomial',
                    valueKind: 'signed integer polynomial',
                    coefficientCount: profile.profile.polynomialDegree,
                    relation:
                        'raw encoder linear combination minus encoded plaintext, divided by plaintext modulus',
                    responseOrder: 3,
                    maskDomain:
                        'sealed-lattice/direct-encrypted-ballot/relation-mask-v1',
                    maskVectorIndex: 3,
                    packageRetention: 'not retained',
                },
                {
                    partitionId: 'projectedBgvNoWrapCarryScalars',
                    valueKind:
                        'signed integer carry scalar per statement-derived projected BGV row',
                    scalarCount: profile.profile.dataPrimes.length * 2 * 6,
                    responseOrder: 6,
                    responseCoefficientBytes: 64,
                    relation:
                        'integer lift of each projected BGV encryption row, with the existing projected residue commitment used as the no-wrap remainder',
                    currentInternalProofEncoding:
                        'encoded in the binary response after one-hot bucket scalars',
                    packageRetention: 'not retained',
                },
            ],
            privateMaterialPolicy: {
                packageRetention:
                    'scores, one-hot rows, encoded plaintext, encryption randomness, errors, carries, and masks are not retained in public packages',
                publicVerificationInputs:
                    'accepted setup handoff, accepted public-key material, package fields, canonical ciphertext bytes, statement hash, and public proof chunks',
            },
        },
    });
}

const directBallotRelationProofProfileHash = (
    kernel: TranscriptCoreKernel,
): string => {
    const profile = kernel.describeBgvRnsProfile();
    const projectedBgvProjectionsPerLimbComponent = 6;
    const projectedBgvCommitmentScalarCount =
        profile.profile.dataPrimes.length *
        2 *
        projectedBgvProjectionsPerLimbComponent;
    const scoreLinearCommitmentScalarCount = 20 * 2;
    const scoreLinearCommitmentBytes = scoreLinearCommitmentScalarCount * 48;
    const relationCommitmentBytes =
        projectedBgvCommitmentScalarCount * 8 + scoreLinearCommitmentBytes;
    const relationResponseScalarCount =
        20 + 20 * 10 + projectedBgvCommitmentScalarCount;
    const relationDimensionWords = [
        profile.profile.polynomialDegree,
        profile.profile.plaintextModulus,
        profile.profile.dataPrimes.length,
        20,
        10,
        4,
        projectedBgvProjectionsPerLimbComponent,
        projectedBgvCommitmentScalarCount,
        scoreLinearCommitmentScalarCount,
        scoreLinearCommitmentBytes,
        relationCommitmentBytes,
        relationResponseScalarCount,
        4 * profile.profile.polynomialDegree * 48 +
            (20 + 20 * 10) * 48 +
            projectedBgvCommitmentScalarCount * 64,
        192,
        48,
        64,
        107,
        2,
    ];
    const witnessPartitionProfileHash = directBallotWitnessPartitionProfileHash(
        kernel,
        profile,
    );
    const arithmeticCertificateHash =
        profile.directBallotArithmeticCertificateHash;
    const soundnessCertificateHash =
        profile.directBallotSoundnessCertificateHash;
    const zeroKnowledgeCertificateHash =
        profile.directBallotZeroKnowledgeCertificateHash;
    const verifierCertificateHash = profile.directBallotVerifierCertificateHash;

    return kernel.deriveProtocolHash({
        namespace: 'BallotValidityProofProfileHash',
        value: {
            profileId: 'direct-encrypted-ballot-validity-relation-v1',
            statementVersion: 3,
            witnessPartitionProfileHash,
            arithmeticCertificateHash,
            soundnessCertificateHash,
            zeroKnowledgeCertificateHash,
            verifierCertificateHash,
            proofEncoding:
                'binary relation transcript with explicit profile and dimension header',
            proofFormatMagic: 'SLDBP003',
            proofFormatVersion: 3,
            relationDimensionWords,
            challengeBits: 192,
            challengeDomain:
                'sealed-lattice/direct-encrypted-ballot/relation-challenge-v1',
            proofBytesDomain:
                'sealed-lattice/direct-encrypted-ballot/relation-proof-bytes-v1',
            projectedBgvRelationProjectionsPerLimbComponent:
                projectedBgvProjectionsPerLimbComponent,
            scoreLinearCommitmentEncoding: 'exact signed integer commitments',
            proofModelStatus:
                'accepted public verifier definition with exact score linkage, projected-BGV budget accounting, committed-trace soundness accounting, zero-knowledge accounting, accepted creation randomness boundary, and appended committed trace proof',
            relation:
                'statement-derived projected BGV all-limb encryption rows with projected no-wrap carry scalars, exact score encoding and one-hot linkage, and a salted masked committed trace proof for support rows, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score rows, projected BGV field rows, and cross-prime no-wrap carry linkage',
            sourceRingDegree: profile.profile.polynomialDegree,
            dataPrimeCount: profile.profile.dataPrimes.length,
        },
    });
};

const directBallotSetupHandoffTestHash = (
    _kernel: TranscriptCoreKernel,
    label: string,
): string =>
    hash512Hex(
        'sealed-lattice/direct-encrypted-ballot/setup-handoff-test-root-v1',
        [textEncoder.encode(directBallotSetupSeed), textEncoder.encode(label)],
    );

const directBallotCreationPolicy = (
    kernel: TranscriptCoreKernel,
): BgvAcceptedSetupHandoff['directBallotEncryptionHandoff']['supportedBallotCreationPolicy'] => {
    const profile = kernel.describeBgvRnsProfile();
    const witnessPartitionProfileHash = directBallotWitnessPartitionProfileHash(
        kernel,
        profile,
    );
    const arithmeticCertificateHash =
        profile.directBallotArithmeticCertificateHash;
    const soundnessCertificateHash =
        profile.directBallotSoundnessCertificateHash;
    const zeroKnowledgeCertificateHash =
        profile.directBallotZeroKnowledgeCertificateHash;
    const verifierCertificateHash = profile.directBallotVerifierCertificateHash;

    return {
        objectType: 'DirectEncryptedBallotCreationPolicy',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        acceptedPackageObjectType: 'EncryptedBallotPackage',
        validityStatementId: 'BallotValidityStatement-v1',
        proofProfileHash: directBallotRelationProofProfileHash(kernel),
        bgvProfileHash: profile.profileHash,
        canonicalCiphertextConventionHash:
            profile.canonicalCiphertextConventionHash,
        batchEncoderHash: profile.batchEncoderHash,
        batchLayoutBindingHash: profile.batchLayoutBindingHash,
        ballotScoreEncodingProfileHash: profile.ballotScoreEncodingProfileHash,
        encryptedBallotLayoutHash: profile.encryptedBallotLayoutHash,
        directBallotReservedSlotRuleHash:
            profile.directBallotReservedSlotRuleHash,
        directBallotEncoderMatrixRoot: profile.directBallotEncoderMatrixRoot,
        witnessPartitionProfileHash,
        arithmeticCertificateHash,
        soundnessCertificateHash,
        zeroKnowledgeCertificateHash,
        verifierCertificateHash,
        optionCount: 20,
        scoreDomain: {
            minimum: 1,
            maximum: 10,
            bucketCount: 10,
            unsetUiValue: 1,
        },
        reservedSlotRule: profile.directBallotReservedSlotRule,
        plaintextModulus: 65537,
        randomnessBoundary:
            'platform CSPRNG material is required; caller-supplied seeds, fixture-labelled randomness, overlapping randomness, and reused randomness are refused',
        creatorReturnPolicy:
            'accepted ballot creation returns public package data, proof chunks, public roots, timing, memory, and proof-size reports only',
        forbiddenPackageFields: [
            'scoreHash',
            'plaintextScores',
            'scoreCommitment',
            'encryptionRandomness',
            'proofWitness',
            'proofRandomnessSeed',
            'fixtureSeed',
            'oracleResult',
            'developmentPlaintext',
        ],
    };
};

type PassivePublicKeyCoefficientTable = {
    readonly modulus: number;
    readonly componentZeroCoefficientsLeHex: string;
    readonly coefficientByteLength: number;
};

type DirectBallotAcceptedPublicKeyMaterialWithoutHandoffRoot = Omit<
    DirectBallotAcceptedPublicKeyMaterial,
    'acceptedSetupHandoffRoot'
>;

const isJsonRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isPassivePublicKeyCoefficientTable = (
    value: unknown,
): value is PassivePublicKeyCoefficientTable =>
    isJsonRecord(value) &&
    Number.isSafeInteger(value.modulus) &&
    typeof value.componentZeroCoefficientsLeHex === 'string' &&
    Number.isSafeInteger(value.coefficientByteLength);

const passivePublicKeyCoefficientTables = (
    setupPublicMaterial: BgvPassiveSetupPackage,
): readonly PassivePublicKeyCoefficientTable[] => {
    const coefficientMaterial =
        setupPublicMaterial.collectivePublicKey.coefficientMaterial;
    if (!isJsonRecord(coefficientMaterial)) {
        throw new Error('passive setup public key coefficient tables missing.');
    }
    const coefficientTables = coefficientMaterial.coefficientTables;
    if (
        !Array.isArray(coefficientTables) ||
        !coefficientTables.every(isPassivePublicKeyCoefficientTable)
    ) {
        throw new Error('passive setup public key coefficient tables missing.');
    }

    return coefficientTables;
};

const acceptedDirectBallotBgvPublicKeyRoot = (
    kernel: TranscriptCoreKernel,
    acceptedPublicKeyMaterial: Pick<
        DirectBallotAcceptedPublicKeyMaterial,
        'commonRandomness' | 'collectivePublicKey'
    >,
): string => {
    const profile = kernel.describeBgvRnsProfile();

    return kernel.deriveProtocolHash({
        namespace: 'BGVPublicKeyRoot',
        value: {
            objectType: 'AcceptedBgvPublicKeyRootBinding',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            bgvProfileHash: profile.profileHash,
            collectivePublicKeyRoot:
                acceptedPublicKeyMaterial.collectivePublicKey
                    .collectivePublicKeyRoot,
            publicMatrixSeedHash:
                acceptedPublicKeyMaterial.commonRandomness.publicMatrixSeedHash,
            publicAPolynomialRoot:
                acceptedPublicKeyMaterial.collectivePublicKey
                    .publicAPolynomialRoot,
            publicKeyShareMaterialSetRoot:
                acceptedPublicKeyMaterial.collectivePublicKey
                    .publicKeyShareMaterialSetRoot,
            publicKeyShareSuccinctProofSetRoot:
                acceptedPublicKeyMaterial.collectivePublicKey
                    .publicKeyShareSuccinctProofSetRoot,
            aggregateCoefficientVectorHashesByLimb:
                acceptedPublicKeyMaterial.collectivePublicKey.aggregateCoefficientVectorsByLimb.map(
                    (aggregateLimb) => ({
                        rnsLimbIndex: aggregateLimb.rnsLimbIndex,
                        rnsPrime: aggregateLimb.rnsPrime,
                        component: aggregateLimb.component,
                        coefficientByteLength:
                            aggregateLimb.coefficientByteLength,
                        coefficientVectorHash512:
                            aggregateLimb.coefficientVectorHash512,
                    }),
                ),
        },
    });
};

const acceptedSetupHandoffForAcceptedPublicKeyMaterial = (
    kernel: TranscriptCoreKernel,
    acceptedPublicKeyMaterial: DirectBallotAcceptedPublicKeyMaterialWithoutHandoffRoot,
): BgvAcceptedSetupHandoff => {
    const profile = kernel.describeBgvRnsProfile();
    const supportedBallotCreationPolicy = directBallotCreationPolicy(kernel);
    const witnessPartitionProfileHash = directBallotWitnessPartitionProfileHash(
        kernel,
        profile,
    );
    const supportedBallotCreationPolicyHash = kernel.deriveProtocolHash({
        namespace: 'DirectEncryptedBallotCreationPolicyHash',
        value: supportedBallotCreationPolicy,
    });
    const handoffWithoutRoot = {
        objectType: 'CollectiveBgvAcceptedSetupHandoff',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ceremonyId: acceptedPublicKeyMaterial.ceremonyId,
        manifestHash: acceptedPublicKeyMaterial.manifestHash,
        rosterHash: acceptedPublicKeyMaterial.rosterHash,
        thresholdProfileHash: acceptedPublicKeyMaterial.thresholdProfileHash,
        setupProfileHash: acceptedPublicKeyMaterial.setupProfileHash,
        qShareHash: acceptedPublicKeyMaterial.qShareHash,
        commitmentProfileHash: acceptedPublicKeyMaterial.commitmentProfileHash,
        setupEpoch: acceptedPublicKeyMaterial.setupEpoch,
        setupPackageHash: acceptedPublicKeyMaterial.setupPackageHash,
        directBallotEncryptionHandoff: {
            status: 'accepted-collective-public-key-root-bound-for-direct-ballot-encryption',
            collectivePublicKeyRoot:
                acceptedPublicKeyMaterial.collectivePublicKeyRoot,
            bgvPublicKeyRoot: acceptedPublicKeyMaterial.bgvPublicKeyRoot,
            bgvProfileHash: profile.profileHash,
            canonicalCiphertextConventionHash:
                profile.canonicalCiphertextConventionHash,
            batchEncoderHash: profile.batchEncoderHash,
            batchLayoutBindingHash: profile.batchLayoutBindingHash,
            ballotScoreEncodingProfileHash:
                profile.ballotScoreEncodingProfileHash,
            encryptedBallotLayoutHash: profile.encryptedBallotLayoutHash,
            directBallotReservedSlotRuleHash:
                acceptedPublicKeyMaterial.directBallotReservedSlotRuleHash,
            directBallotEncoderMatrixRoot:
                acceptedPublicKeyMaterial.directBallotEncoderMatrixRoot,
            witnessPartitionProfileHash,
            arithmeticCertificateHash:
                profile.directBallotArithmeticCertificateHash,
            soundnessCertificateHash:
                profile.directBallotSoundnessCertificateHash,
            zeroKnowledgeCertificateHash:
                profile.directBallotZeroKnowledgeCertificateHash,
            verifierCertificateHash:
                profile.directBallotVerifierCertificateHash,
            ballotValidityProofProfileHash:
                directBallotRelationProofProfileHash(kernel),
            publicKeyShareMaterialSetRoot:
                acceptedPublicKeyMaterial.publicKeyShareMaterialSetRoot,
            publicKeyShareSuccinctProofSetRoot:
                acceptedPublicKeyMaterial.publicKeyShareSuccinctProofSetRoot,
            acceptedPublicKeyMaterial: {
                materialSource:
                    'accepted public-key share material with accepted public-key share proofs',
                collectivePublicKeyRoot:
                    acceptedPublicKeyMaterial.collectivePublicKeyRoot,
                bgvPublicKeyRoot: acceptedPublicKeyMaterial.bgvPublicKeyRoot,
                publicKeyShareMaterialSetRoot:
                    acceptedPublicKeyMaterial.publicKeyShareMaterialSetRoot,
                publicKeyShareSuccinctProofSetRoot:
                    acceptedPublicKeyMaterial.publicKeyShareSuccinctProofSetRoot,
            },
            supportedBallotCreationPolicy,
            supportedBallotCreationPolicyHash,
        },
        publicAggregationHandoff: {
            status: 'accepted-public-ciphertext-aggregation-bound-to-setup-context-and-collective-public-key-root',
            thresholdShareCommitmentRoot: directBallotSetupHandoffTestHash(
                kernel,
                'threshold share commitment root',
            ),
        },
        boundedEvaluatorReplayHandoff: {
            status: 'accepted-public-evaluation-keys-bound-to-frozen-evaluator-schedule',
            evaluatorKeyScheduleRoot: directBallotSetupHandoffTestHash(
                kernel,
                'evaluator key schedule root',
            ),
            relinearizationKeyShareRoundsRoot: directBallotSetupHandoffTestHash(
                kernel,
                'relinearization key share rounds root',
            ),
            trusteeEvaluationKeyProofSetRoot: directBallotSetupHandoffTestHash(
                kernel,
                'trustee evaluation key proof set root',
            ),
            evaluationKeySetHash: directBallotSetupHandoffTestHash(
                kernel,
                'evaluation key set hash',
            ),
        },
        futureTargetDecryptionHandoff: {
            status: 'target decryption remains downstream',
            targetDecryptionProfileId: 'BGV-RNS-AsyncTargetDecryption-v1',
            claimBoundary:
                'target decryption remains downstream and any target-decryption readiness claim is refused until Q_target, smudging, C1-C4, and decryption-share proof closure exist',
        },
        certificateRoots: {
            setupCommitmentSecurityCertificateHash:
                directBallotSetupHandoffTestHash(
                    kernel,
                    'setup commitment security certificate hash',
                ),
            setupTransportCertificateHash: directBallotSetupHandoffTestHash(
                kernel,
                'setup transport certificate hash',
            ),
            setupProofAccountingCertificateHash:
                directBallotSetupHandoffTestHash(
                    kernel,
                    'setup proof accounting certificate hash',
                ),
            setupKeyCorrectnessCertificateHash:
                directBallotSetupHandoffTestHash(
                    kernel,
                    'setup key correctness certificate hash',
                ),
            activeStaticSetupTheoremCertificateHash:
                directBallotSetupHandoffTestHash(
                    kernel,
                    'active static setup theorem certificate hash',
                ),
            heSecurityCertificateHash: directBallotSetupHandoffTestHash(
                kernel,
                'HE security certificate hash',
            ),
        },
    } satisfies Omit<BgvAcceptedSetupHandoff, 'acceptedSetupHandoffRoot'>;

    return {
        ...handoffWithoutRoot,
        acceptedSetupHandoffRoot: kernel.deriveProtocolHash({
            namespace: 'AcceptedSetupHandoffRoot',
            value: handoffWithoutRoot,
        }),
    };
};

export const acceptedDirectBallotPublicMaterialForSetupPublicMaterial = (
    kernel: TranscriptCoreKernel,
    setupPublicMaterial: BgvPassiveSetupPackage,
): {
    readonly acceptedPublicKeyMaterial: DirectBallotAcceptedPublicKeyMaterial;
    readonly acceptedSetupHandoff: BgvAcceptedSetupHandoff;
} => {
    const profile = kernel.describeBgvRnsProfile();
    const publicMatrixSeedHash = directBallotSetupHandoffTestHash(
        kernel,
        'accepted public matrix seed hash',
    );
    const publicDerivations = kernel.deriveCollectiveBgvSetupPublicDerivations({
        publicMatrixSeedHash,
    });
    const publicKeyShareMaterialSetRoot = directBallotSetupHandoffTestHash(
        kernel,
        'public key share material set root',
    );
    const publicKeyShareSuccinctProofSetRoot = directBallotSetupHandoffTestHash(
        kernel,
        'public key share succinct proof set root',
    );
    const ballotValidityProofProfileHash =
        directBallotRelationProofProfileHash(kernel);
    const aggregateCoefficientVectorsByLimb = passivePublicKeyCoefficientTables(
        setupPublicMaterial,
    ).map((coefficientTable, rnsLimbIndex) => {
        if (
            coefficientTable.modulus !==
            profile.profile.dataPrimes[rnsLimbIndex]
        ) {
            throw new Error(
                'passive setup public key coefficient table order mismatch.',
            );
        }
        const coefficientBytes = hexToBytes(
            coefficientTable.componentZeroCoefficientsLeHex,
        );

        return {
            rnsLimbIndex,
            rnsPrime: coefficientTable.modulus,
            component: 'b' as const,
            coefficientByteLength: coefficientTable.coefficientByteLength,
            coefficientVectorHash512: hash512Hex(
                publicKeyShareCoefficientVectorHashDomain,
                [coefficientBytes],
            ),
            coefficientsLeHex: coefficientTable.componentZeroCoefficientsLeHex,
        };
    });
    const collectivePublicKeyWithoutRoot = {
        objectType: 'CollectivePublicKey' as const,
        objectVersion: 1 as const,
        setupProfileId: 'CollectiveBgvSetup-v1' as const,
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'public-key-share',
        proofVerificationStatus:
            'succinct-public-key-share-argument-verified-with-accepted-proof-accounting',
        proofModelStatus:
            'succinct-public-key-share-argument-accounting-accepted',
        aggregationStatus:
            'succinct-proof-aggregated-with-accepted-setup-proof-accounting',
        materialEncoding: 'embedded-full-collective-public-key-coefficients',
        ceremonyId: setupPublicMaterial.setupInputs.ceremonyId,
        manifestHash: setupPublicMaterial.setupInputs.manifestHash,
        rosterHash: setupPublicMaterial.setupInputs.rosterHash,
        setupProfileHash: profile.profileHash,
        qShareHash: directBallotSetupHandoffTestHash(kernel, 'q share hash'),
        carryAwareVssShareRelationProfileHash: directBallotSetupHandoffTestHash(
            kernel,
            'carry-aware VSS share relation profile hash',
        ),
        commitmentProfileHash: directBallotSetupHandoffTestHash(
            kernel,
            'commitment profile hash',
        ),
        setupEpoch: 'direct-ballot-test-setup-epoch',
        participantCount: 10,
        rnsLimbCount: profile.profile.dataPrimes.length,
        ringDegree: profile.profile.polynomialDegree,
        publicMatrixSeedHash,
        publicKeyCrpRoot: publicDerivations.crpRoots.publicKeyCrpRoot,
        publicAPolynomialRoot:
            publicDerivations.bgvPublicA.publicPolynomialRoot,
        sameSecretConsistencyRoot: directBallotSetupHandoffTestHash(
            kernel,
            'same secret consistency root',
        ),
        sameSecretProofSetRoot: directBallotSetupHandoffTestHash(
            kernel,
            'same secret proof set root',
        ),
        sameSecretProofFamilyBindingRoot: directBallotSetupHandoffTestHash(
            kernel,
            'same secret proof family binding root',
        ),
        publicKeyShareSetRoot: directBallotSetupHandoffTestHash(
            kernel,
            'public key share set root',
        ),
        publicKeyShareProofSetRoot: directBallotSetupHandoffTestHash(
            kernel,
            'public key share proof set root',
        ),
        publicKeyShareMaterialSetRoot,
        publicKeyShareSuccinctProofSetRoot,
        sourceShareMaterialRoots: [],
        aggregateCoefficientVectorsByLimb,
    };
    const collectivePublicKey = {
        ...collectivePublicKeyWithoutRoot,
        collectivePublicKeyRoot: kernel.deriveProtocolHash({
            namespace: 'CollectivePublicKeyRoot',
            value: collectivePublicKeyWithoutRoot,
        }),
    };
    const acceptedPublicKeyMaterialWithoutBgvRoot = {
        objectType: 'DirectBallotAcceptedPublicKeyMaterial' as const,
        objectVersion: 1 as const,
        setupProfileId: 'CollectiveBgvSetup-v1' as const,
        ceremonyId: setupPublicMaterial.setupInputs.ceremonyId,
        manifestHash: setupPublicMaterial.setupInputs.manifestHash,
        rosterHash: setupPublicMaterial.setupInputs.rosterHash,
        thresholdProfileHash:
            setupPublicMaterial.setupInputs.thresholdProfileHash,
        setupProfileHash: profile.profileHash,
        qShareHash: directBallotSetupHandoffTestHash(kernel, 'q share hash'),
        commitmentProfileHash: directBallotSetupHandoffTestHash(
            kernel,
            'commitment profile hash',
        ),
        setupEpoch: 'direct-ballot-test-setup-epoch',
        setupPackageHash: setupPublicMaterial.setupPackageHash,
        bgvProfileHash: profile.profileHash,
        batchEncoderHash: profile.batchEncoderHash,
        batchLayoutBindingHash: profile.batchLayoutBindingHash,
        ballotScoreEncodingProfileHash: profile.ballotScoreEncodingProfileHash,
        encryptedBallotLayoutHash: profile.encryptedBallotLayoutHash,
        directBallotReservedSlotRuleHash:
            profile.directBallotReservedSlotRuleHash,
        directBallotEncoderMatrixRoot: profile.directBallotEncoderMatrixRoot,
        arithmeticCertificateHash:
            profile.directBallotArithmeticCertificateHash,
        soundnessCertificateHash: profile.directBallotSoundnessCertificateHash,
        zeroKnowledgeCertificateHash:
            profile.directBallotZeroKnowledgeCertificateHash,
        verifierCertificateHash: profile.directBallotVerifierCertificateHash,
        ballotValidityProofProfileHash,
        collectivePublicKeyRoot: collectivePublicKey.collectivePublicKeyRoot,
        publicKeyShareMaterialSetRoot,
        publicKeyShareSuccinctProofSetRoot,
        commonRandomness: {
            publicMatrixSeedHash,
            publicDerivations,
        },
        collectivePublicKey,
    };
    const acceptedPublicKeyMaterialWithoutHandoffRoot = {
        ...acceptedPublicKeyMaterialWithoutBgvRoot,
        bgvPublicKeyRoot: acceptedDirectBallotBgvPublicKeyRoot(
            kernel,
            acceptedPublicKeyMaterialWithoutBgvRoot,
        ),
    } satisfies DirectBallotAcceptedPublicKeyMaterialWithoutHandoffRoot;
    const acceptedSetupHandoff =
        acceptedSetupHandoffForAcceptedPublicKeyMaterial(
            kernel,
            acceptedPublicKeyMaterialWithoutHandoffRoot,
        );

    return {
        acceptedPublicKeyMaterial: {
            ...acceptedPublicKeyMaterialWithoutHandoffRoot,
            acceptedSetupHandoffRoot:
                acceptedSetupHandoff.acceptedSetupHandoffRoot,
        },
        acceptedSetupHandoff,
    };
};

export const directBallotActionContextHash = (): string =>
    deriveProtocolHash('ActionContextHash', {
        action: 'direct encrypted ballot node wasm smoke',
    });

export type DirectEncryptedBallotInput = {
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
    readonly actionContextHash: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly scores: readonly number[];
};

type DirectBallotProofMaskRandomnessInput = {
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
};

type DirectBallotEncryptionRandomnessInput = {
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
};

export const createDirectBallotInputs = (
    ballotCount: number,
): readonly DirectEncryptedBallotInput[] => {
    if (!Number.isInteger(ballotCount) || ballotCount < 1 || ballotCount > 20) {
        throw new Error('ballotCount must be an integer from 1 through 20.');
    }

    return Array.from(
        { length: ballotCount },
        (_unusedBallot, ballotIndex) => ({
            voterIdentity: `voter-node-wasm-${String(ballotIndex + 1).padStart(2, '0')}`,
            voterRosterPosition: ballotIndex,
            actionContextHash: deriveProtocolHash('ActionContextHash', {
                action: 'direct encrypted ballot node wasm smoke',
                ballotIndex,
            }),
            recoveryEpoch: 0,
            deviceEpoch: 0,
            scores: directBallotScores.map((_unusedScore, optionIndex) => {
                const score = ((optionIndex + ballotIndex) % 10) + 1;

                return score;
            }),
        }),
    );
};

const defaultDirectBallotInputs = (): readonly DirectEncryptedBallotInput[] => [
    {
        voterIdentity: 'voter-node-wasm-1',
        voterRosterPosition: 0,
        actionContextHash: directBallotActionContextHash(),
        recoveryEpoch: 0,
        deviceEpoch: 0,
        scores: directBallotScores,
    },
];

const createRandomnessHexes = (input: {
    readonly developmentRandomnessOverrideAcknowledged: boolean | undefined;
    readonly label: string;
    readonly requiredCount: number;
    readonly suppliedRandomnessHexes: readonly string[] | undefined;
}): {
    readonly randomnessHexes: readonly string[];
    readonly sources: readonly (
        | 'fresh-csprng'
        | 'development-deterministic-fixture'
    )[];
} => {
    if (
        input.suppliedRandomnessHexes !== undefined &&
        input.suppliedRandomnessHexes.length !== input.requiredCount
    ) {
        throw new RangeError(
            `${input.label} length must match the required count.`,
        );
    }

    return Array.from(
        { length: input.requiredCount },
        (_unused, randomnessIndex) => {
            const suppliedRandomnessHex =
                input.suppliedRandomnessHexes?.[randomnessIndex];
            if (
                suppliedRandomnessHex !== undefined &&
                input.developmentRandomnessOverrideAcknowledged !== true
            ) {
                throw new RangeError(
                    `Caller-supplied ${input.label} requires developmentRandomnessOverrideAcknowledged.`,
                );
            }

            const randomnessSource:
                | 'fresh-csprng'
                | 'development-deterministic-fixture' =
                suppliedRandomnessHex === undefined
                    ? 'fresh-csprng'
                    : 'development-deterministic-fixture';

            return {
                randomnessHex: suppliedOrFreshRandomnessHex(
                    suppliedRandomnessHex,
                ),
                randomnessSource,
            };
        },
    ).reduce<{
        randomnessHexes: string[];
        sources: ('fresh-csprng' | 'development-deterministic-fixture')[];
    }>(
        (accumulatedRandomness, proofRandomness) => {
            accumulatedRandomness.randomnessHexes.push(
                proofRandomness.randomnessHex,
            );
            accumulatedRandomness.sources.push(
                proofRandomness.randomnessSource,
            );

            return accumulatedRandomness;
        },
        { randomnessHexes: [], sources: [] },
    );
};

const createBallotEncryptionRandomness = (
    input: DirectBallotEncryptionRandomnessInput & {
        readonly ballotCount: number;
    },
): Record<string, unknown> => {
    const encryptionSeedHexes = createRandomnessHexes({
        developmentRandomnessOverrideAcknowledged:
            input.developmentRandomnessOverrideAcknowledged,
        label: 'encryptionSeedHexes',
        requiredCount: input.ballotCount,
        suppliedRandomnessHexes: input.ballotEncryptionSeedHexes,
    });
    const source = encryptionSeedHexes.sources.find(
        (randomnessSource) => randomnessSource !== 'fresh-csprng',
    );

    return {
        source: source ?? 'fresh-csprng',
        encryptionSeedHexes: encryptionSeedHexes.randomnessHexes,
    };
};

const createProofMaskRandomness = (
    input: DirectBallotProofMaskRandomnessInput & {
        readonly ballotCount: number;
    },
): Record<string, unknown> => {
    const ballotProofRandomnessHexes = createRandomnessHexes({
        developmentRandomnessOverrideAcknowledged:
            input.developmentRandomnessOverrideAcknowledged,
        label: 'ballotProofRandomnessHexes',
        requiredCount: input.ballotCount,
        suppliedRandomnessHexes: input.ballotProofRandomnessHexes,
    });
    const source = ballotProofRandomnessHexes.sources.find(
        (randomnessSource) => randomnessSource !== 'fresh-csprng',
    );

    return {
        source: source ?? 'fresh-csprng',
        ballotProofRandomnessHexes: ballotProofRandomnessHexes.randomnessHexes,
    };
};

export const runInternalKernelCommand = async <Result>(
    request: Record<string, unknown>,
): Promise<Result> => {
    const bytes = await resolveKernelBytes(wasmKernelUrl);
    const instantiatedSource = await WebAssembly.instantiate(bytes, {});
    const exports = instantiatedSource.instance
        .exports as TranscriptCoreKernelExports;
    const memory = resolveMemory(exports);
    const allocate = resolveNumberExport(
        exports,
        'sealed_lattice_allocate',
    ) as (length: number) => number;
    const deallocate = resolveNumberExport(
        exports,
        'sealed_lattice_deallocate',
    );
    const commandWithLength = resolveNumberExport(
        exports,
        'sealed_lattice_transcript_core_command_with_length',
    ) as (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;

    return runKernelCommand<Result>(
        memory,
        allocate,
        deallocate,
        commandWithLength,
        request as unknown as TranscriptCoreKernelCommand,
    );
};

export const runDirectEncryptedBallot = (input: {
    readonly ballots?: readonly DirectEncryptedBallotInput[];
    readonly ballotEncryptionSeedHexes?: readonly string[];
    readonly ballotProofRandomnessHexes?: readonly string[];
    readonly developmentRandomnessOverrideAcknowledged?: boolean;
    readonly setupPackage: BgvPassiveSetupPackage;
    readonly setupSeed?: string;
    readonly topCount?: number;
    readonly topCounts?: readonly number[];
    readonly publicEvaluationKeyMaterial?: Record<string, unknown>;
    readonly targetFinalityPolicyHash?: string;
}): Promise<DirectEncryptedBallotResult> => {
    const ballots = input.ballots ?? defaultDirectBallotInputs();

    return runInternalKernelCommand<DirectEncryptedBallotResult>({
        command: 'RunDirectEncryptedBallot',
        setupPackage: input.setupPackage,
        setupPrivateWitness: {
            setupSeed: input.setupSeed ?? directBallotSetupSeed,
        },
        ballotEncryptionRandomness: createBallotEncryptionRandomness({
            ballotCount: ballots.length,
            ballotEncryptionSeedHexes: input.ballotEncryptionSeedHexes,
            developmentRandomnessOverrideAcknowledged:
                input.developmentRandomnessOverrideAcknowledged,
        }),
        proofMaskRandomness: createProofMaskRandomness({
            ballotCount: ballots.length,
            ballotProofRandomnessHexes: input.ballotProofRandomnessHexes,
            developmentRandomnessOverrideAcknowledged:
                input.developmentRandomnessOverrideAcknowledged,
        }),
        ...(input.topCount === undefined ? {} : { topCount: input.topCount }),
        ...(input.topCounts === undefined
            ? {}
            : { topCounts: input.topCounts }),
        ...(input.publicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  publicEvaluationKeyMaterial:
                      input.publicEvaluationKeyMaterial,
              }),
        ...(input.targetFinalityPolicyHash === undefined
            ? {}
            : { targetFinalityPolicyHash: input.targetFinalityPolicyHash }),
        ballots,
    });
};

export const createDirectEncryptedBallotPackages = (input: {
    readonly ballots?: readonly DirectEncryptedBallotInput[];
    readonly acceptedPublicKeyMaterial: DirectBallotAcceptedPublicKeyMaterial;
    readonly acceptedSetupHandoff: BgvAcceptedSetupHandoff;
}): Promise<DirectEncryptedBallotPackageCreationResult> => {
    const ballots = input.ballots ?? defaultDirectBallotInputs();

    return runInternalKernelCommand<DirectEncryptedBallotPackageCreationResult>(
        {
            command: 'CreateDirectEncryptedBallotPackages',
            acceptedPublicKeyMaterial: input.acceptedPublicKeyMaterial,
            acceptedSetupHandoff: input.acceptedSetupHandoff,
            ballotEncryptionRandomness: createBallotEncryptionRandomness({
                ballotCount: ballots.length,
            }),
            proofMaskRandomness: createProofMaskRandomness({
                ballotCount: ballots.length,
            }),
            ballots,
        },
    );
};

export const verifyDirectEncryptedBallotPackage = (input: {
    readonly encryptedBallotPackage: DirectEncryptedBallotPackage;
    readonly proofChunks: readonly DirectEncryptedBallotProofChunk[];
    readonly acceptedPublicKeyMaterial: DirectBallotAcceptedPublicKeyMaterial;
    readonly acceptedSetupHandoff: BgvAcceptedSetupHandoff;
    readonly voterSigningPublicKeyHash: string;
}): Promise<DirectEncryptedBallotPackageVerificationResult> =>
    runInternalKernelCommand<DirectEncryptedBallotPackageVerificationResult>({
        command: 'VerifyDirectEncryptedBallotPackage',
        acceptedPublicKeyMaterial: input.acceptedPublicKeyMaterial,
        acceptedSetupHandoff: input.acceptedSetupHandoff,
        voterSigningPublicKeyHash: input.voterSigningPublicKeyHash,
        encryptedBallotPackage: input.encryptedBallotPackage,
        proofChunks: input.proofChunks,
    });
