import { currentRecoveryEpochMap } from './fixtures.js';
import {
    assertFailure,
    expectedVerifierFailure,
    type FailureExpectation,
} from './negative-check-assertions.js';
import {
    lowerHexHash,
    type ContributionBuild,
    type NegativeCheck,
    type TranscriptCoreKernel,
    type Variant,
} from './shared.js';

import { canonicalJson, deriveProtocolHash } from '#packages/crypto/src/index';
import { selectFirstValidAggregateContributions } from '#packages/protocol/src/ballot-privacy/index';
import type {
    AggregateContribution,
    ProtocolHash,
} from '#packages/types/src/index';

export { runSelectionNegativeChecks } from './selection-negative-checks.js';

type CheapNegativeCase = readonly [
    check: string,
    expectation: FailureExpectation,
    action: () => unknown,
];

const mutateLastHexDigit = (value: unknown): string => {
    const hex = String(value);
    const replacement = hex.endsWith('0') ? '1' : '0';

    return `${hex.slice(0, -1)}${replacement}`;
};

const hexToByteArray = (hex: string): number[] => {
    if (!/^(?:[a-f0-9]{2})*$/u.test(hex)) {
        throw new Error('Canonical BGV bytes must be lowercase hex.');
    }

    return Array.from({ length: hex.length / 2 }, (_unused, byteIndex) =>
        Number.parseInt(hex.slice(byteIndex * 2, byteIndex * 2 + 2), 16),
    );
};

const byteArrayToHex = (bytes: readonly number[]): string =>
    bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');

const encodeCanonicalVaruint = (value: number): readonly number[] => {
    if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > Number.MAX_SAFE_INTEGER
    ) {
        throw new Error('Canonical varuint value is outside the safe range.');
    }
    const encoded: number[] = [];
    let remainingValue = value;
    do {
        const nextByte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        encoded.push(nextByte | (remainingValue === 0 ? 0 : 0x80));
    } while (remainingValue !== 0);

    return encoded;
};

const readCanonicalVaruint = (
    bytes: readonly number[],
    startOffset: number,
): {
    readonly endOffset: number;
    readonly startOffset: number;
    readonly value: number;
} => {
    let value = 0;
    let multiplier = 1;
    let offset = startOffset;
    while (offset < bytes.length) {
        const byte = bytes[offset];
        value += (byte & 0x7f) * multiplier;
        offset += 1;
        if ((byte & 0x80) === 0) {
            const canonical = encodeCanonicalVaruint(value);
            const consumed = bytes.slice(startOffset, offset);
            if (
                canonical.length !== consumed.length ||
                canonical.some(
                    (canonicalByte, byteIndex) =>
                        canonicalByte !== consumed[byteIndex],
                )
            ) {
                throw new Error('Canonical varuint is not minimally encoded.');
            }

            return { endOffset: offset, startOffset, value };
        }
        multiplier *= 128;
        if (multiplier > Number.MAX_SAFE_INTEGER) {
            throw new Error('Canonical varuint exceeds the safe range.');
        }
    }

    throw new Error('Canonical varuint is truncated.');
};

const readCanonicalString = (
    bytes: readonly number[],
    startOffset: number,
): {
    readonly endOffset: number;
    readonly value: string;
} => {
    const length = readCanonicalVaruint(bytes, startOffset);
    const stringStartOffset = length.endOffset;
    const stringEndOffset = stringStartOffset + length.value;
    if (stringEndOffset > bytes.length) {
        throw new Error('Canonical string is truncated.');
    }

    return {
        endOffset: stringEndOffset,
        value: Buffer.from(
            bytes.slice(stringStartOffset, stringEndOffset),
        ).toString('utf8'),
    };
};

const mutateFirstCanonicalBgvCiphertextResidue = (value: unknown): string => {
    const bytes = hexToByteArray(String(value));
    let offset = 0;
    const magic = readCanonicalString(bytes, offset);
    offset = magic.endOffset;
    const objectVersion = readCanonicalVaruint(bytes, offset);
    offset = objectVersion.endOffset;
    const objectKind = readCanonicalString(bytes, offset);
    offset = objectKind.endOffset;
    if (
        magic.value !== 'sealed-lattice-bgv-rns-canonical-object-v1' ||
        objectVersion.value !== 1 ||
        objectKind.value !== 'ciphertext'
    ) {
        throw new Error('Canonical BGV object is not a v1 ciphertext.');
    }
    const componentCount = readCanonicalVaruint(bytes, offset);
    offset = componentCount.endOffset;
    if (componentCount.value < 1) {
        throw new Error('Canonical BGV ciphertext has no components.');
    }

    offset = readCanonicalString(bytes, offset).endOffset;
    offset = readCanonicalString(bytes, offset).endOffset;
    offset = readCanonicalVaruint(bytes, offset).endOffset;
    const coefficientCount = readCanonicalVaruint(bytes, offset);
    offset = coefficientCount.endOffset;
    offset = readCanonicalString(bytes, offset).endOffset;
    offset = readCanonicalString(bytes, offset).endOffset;
    const modulusCount = readCanonicalVaruint(bytes, offset);
    offset = modulusCount.endOffset;
    const moduli: number[] = [];
    for (
        let modulusIndex = 0;
        modulusIndex < modulusCount.value;
        modulusIndex += 1
    ) {
        const modulus = readCanonicalVaruint(bytes, offset);
        offset = modulus.endOffset;
        moduli.push(modulus.value);
    }
    const residueLimbCount = readCanonicalVaruint(bytes, offset);
    offset = residueLimbCount.endOffset;
    if (residueLimbCount.value !== modulusCount.value || moduli.length === 0) {
        throw new Error(
            'Canonical BGV ciphertext has inconsistent residue limbs.',
        );
    }
    const firstResidueCount = readCanonicalVaruint(bytes, offset);
    offset = firstResidueCount.endOffset;
    if (firstResidueCount.value !== coefficientCount.value) {
        throw new Error(
            'Canonical BGV ciphertext residue count does not match coefficient count.',
        );
    }
    const firstResidue = readCanonicalVaruint(bytes, offset);
    const mutatedResidue = (firstResidue.value + 1) % moduli[0];
    const encodedMutatedResidue = encodeCanonicalVaruint(mutatedResidue);

    return byteArrayToHex([
        ...bytes.slice(0, firstResidue.startOffset),
        ...encodedMutatedResidue,
        ...bytes.slice(firstResidue.endOffset),
    ]);
};

const outOfBoundSignedI256SharedWitnessResponseHex = `${'00'.repeat(30)}0100`;

const mutateFirstSignedI256ResponseOutOfBound = (value: unknown): string => {
    const hex = String(value);

    return `${outOfBoundSignedI256SharedWitnessResponseHex}${hex.slice(64)}`;
};

const bridgeSharedWitnessProofHash = (
    bridgeSharedWitnessProof: unknown,
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        bridgeSharedWitnessProof,
        purpose: 'sealed-lattice-aggregate-bridge-shared-witness-proof-hash-v1',
    });

const bgvRandomnessBoundProofStatusHash = (
    bgvRandomnessBoundProofStatusEvidence: unknown,
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        bgvRandomnessBoundProofStatusEvidence,
        purpose:
            'sealed-lattice-aggregate-bridge-bgv-randomness-bound-status-v1',
    });

const bgvRandomnessBoundCommitmentHash = (
    bgvRandomnessBoundCommitment: unknown,
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        bgvRandomnessBoundCommitment,
        purpose:
            'sealed-lattice-aggregate-bridge-bgv-randomness-bound-commitment-v1',
    });

const sharedWitnessZeroKnowledgeStatusHash = (
    sharedWitnessZeroKnowledgeStatusEvidence: unknown,
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        sharedWitnessZeroKnowledgeStatusEvidence,
        purpose:
            'sealed-lattice-aggregate-bridge-shared-witness-zero-knowledge-status-v1',
    });

const setupPackageWithCanonicalHash = (
    setupPackage: Record<string, unknown>,
): Record<string, unknown> => {
    const hashInput = structuredClone(setupPackage);
    delete hashInput.setupPackageHash;

    return {
        ...setupPackage,
        setupPackageHash: deriveProtocolHash(
            'BGVPassiveSetupPackageHash',
            hashInput,
        ),
    };
};

const refreshBridgeProofSubproofHashes = (
    proof: Record<string, unknown>,
): void => {
    if (
        typeof proof.bridgeSharedWitnessProof === 'object' &&
        proof.bridgeSharedWitnessProof !== null
    ) {
        proof.bridgeSharedWitnessProofHash = bridgeSharedWitnessProofHash(
            proof.bridgeSharedWitnessProof,
        );
    }
    if (typeof proof.bridgeSharedWitnessProofHash === 'string') {
        if (
            typeof proof.sharedWitnessZeroKnowledgeStatusEvidence ===
                'object' &&
            proof.sharedWitnessZeroKnowledgeStatusEvidence !== null
        ) {
            (
                proof.sharedWitnessZeroKnowledgeStatusEvidence as Record<
                    string,
                    unknown
                >
            ).bridgeSharedWitnessProofHash = proof.bridgeSharedWitnessProofHash;
        }
        if (
            typeof proof.bgvRandomnessBoundProofStatusEvidence === 'object' &&
            proof.bgvRandomnessBoundProofStatusEvidence !== null
        ) {
            (
                proof.bgvRandomnessBoundProofStatusEvidence as Record<
                    string,
                    unknown
                >
            ).bridgeSharedWitnessProofHash = proof.bridgeSharedWitnessProofHash;
        }
    }
    if (
        typeof proof.sharedWitnessZeroKnowledgeStatusEvidence === 'object' &&
        proof.sharedWitnessZeroKnowledgeStatusEvidence !== null
    ) {
        proof.sharedWitnessZeroKnowledgeStatusHash =
            sharedWitnessZeroKnowledgeStatusHash(
                proof.sharedWitnessZeroKnowledgeStatusEvidence,
            );
    }
    if (
        typeof proof.bgvRandomnessBoundProofStatusEvidence === 'object' &&
        proof.bgvRandomnessBoundProofStatusEvidence !== null
    ) {
        proof.bgvRandomnessBoundProofStatusHash =
            bgvRandomnessBoundProofStatusHash(
                proof.bgvRandomnessBoundProofStatusEvidence,
            );
    }
};

const bridgeWithMutatedProof = (
    bridgeEncryption: Record<string, unknown>,
    proofMutator: (proof: Record<string, unknown>) => void,
): Record<string, unknown> => {
    const proof = JSON.parse(
        Buffer.from(
            String(bridgeEncryption.bridgeProofBytesHex),
            'hex',
        ).toString('utf8'),
    ) as Record<string, unknown>;
    proofMutator(proof);
    refreshBridgeProofSubproofHashes(proof);
    const bridgeProofBytesHex = Buffer.from(
        canonicalJson(proof),
        'utf8',
    ).toString('hex');
    const bridgeProofBytesHash = deriveProtocolHash('ProofBytesHash', {
        proofBytesHex: bridgeProofBytesHex,
        purpose: 'sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1',
    });

    return {
        ...bridgeEncryption,
        bridgeProofBytesHex,
        bridgeProofBytesHash,
        ...(typeof proof.bridgeSharedWitnessProofHash === 'string'
            ? {
                  bridgeSharedWitnessProofHash:
                      proof.bridgeSharedWitnessProofHash,
              }
            : {}),
        ...(typeof proof.sharedWitnessZeroKnowledgeStatusHash === 'string'
            ? {
                  sharedWitnessZeroKnowledgeStatusHash:
                      proof.sharedWitnessZeroKnowledgeStatusHash,
              }
            : {}),
        ...(typeof proof.bgvRandomnessBoundProofStatusHash === 'string'
            ? {
                  bgvRandomnessBoundProofStatusHash:
                      proof.bgvRandomnessBoundProofStatusHash,
              }
            : {}),
        bridgeProofRoot: deriveProtocolHash('BridgeProofRecordHash', {
            aggregateDerivationComponentHash:
                bridgeEncryption.aggregateDerivationComponentHash,
            aggregateDerivationStatementHash:
                bridgeEncryption.aggregateDerivationStatementHash,
            bgvPublicKeyRoot: bridgeEncryption.bgvPublicKeyRoot,
            bridgeProofProfileHash: bridgeEncryption.bridgeProofProfileHash,
            bridgeProofStatementHash: bridgeEncryption.bridgeProofStatementHash,
            collectivePublicKeyRoot: bridgeEncryption.collectivePublicKeyRoot,
            collectivePublicKeyCoefficientRoot:
                bridgeEncryption.collectivePublicKeyCoefficientRoot,
            encryptedAggregateShareCiphertextRoot:
                bridgeEncryption.encryptedAggregateShareCiphertextRoot,
            ...(typeof proof.bridgeSharedWitnessProofHash === 'string'
                ? {
                      bridgeSharedWitnessProofHash:
                          proof.bridgeSharedWitnessProofHash,
                  }
                : {}),
            ...(typeof proof.sharedWitnessZeroKnowledgeStatusHash === 'string'
                ? {
                      sharedWitnessZeroKnowledgeStatusHash:
                          proof.sharedWitnessZeroKnowledgeStatusHash,
                  }
                : {}),
            ...(typeof proof.bgvRandomnessBoundProofStatusHash === 'string'
                ? {
                      bgvRandomnessBoundProofStatusHash:
                          proof.bgvRandomnessBoundProofStatusHash,
                  }
                : {}),
            proofBytesHash: bridgeProofBytesHash,
            purpose: 'sealed-lattice-aggregate-bridge-encryption-proof-root-v1',
        }),
    };
};

export const runCheapNegativeChecks = (input: {
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly contribution: ContributionBuild;
    readonly heParamHash: ProtocolHash;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const base = {
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
        suite: 'cheap' as const,
    };
    const verifyBridge = (
        aggregateDerivationComponent: unknown,
        bridgeEncryption: unknown,
        setupPackage: unknown,
        aggregateSelectionPolicyHash = input.aggregateSelectionPolicyHash,
    ): unknown =>
        input.kernel.verifyAggregateBridgeEncryption({
            aggregateDerivationComponent,
            aggregateSelectionPolicyHash,
            bridgeEncryption,
            bridgeWitnessPrivacyProfileHash:
                input.bridgeWitnessPrivacyProfileHash,
            heParamHash: input.heParamHash,
            setupPackage,
        });
    const component = input.contribution.aggregateDerivationComponent;
    const bridgeEncryption = input.contribution.bridgeEncryption;
    const checks: readonly CheapNegativeCase[] = [
        [
            'wrong n',
            expectedVerifierFailure(
                'participant-count statement binding',
                /participant|statement|target contract|variant/iu,
            ),
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            participantCount:
                                component.statement.participantCount + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong m',
            expectedVerifierFailure(
                'option-count statement binding',
                /option|statement|target contract|variant/iu,
            ),
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            optionCount: component.statement.optionCount + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong shareVectorWidth',
            expectedVerifierFailure(
                'share-vector-width statement binding',
                /shareVectorWidth|share vector|statement|target contract/iu,
            ),
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            shareVectorWidth:
                                component.statement.shareVectorWidth + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong threshold profile hash',
            expectedVerifierFailure(
                'threshold-profile setup binding',
                /threshold|setup|profile|statement|target contract/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    bridgeEncryption,
                    setupPackageWithCanonicalHash({
                        ...input.setupPackage,
                        setupInputs: {
                            ...(input.setupPackage.setupInputs as Record<
                                string,
                                unknown
                            >),
                            thresholdProfileHash: lowerHexHash(
                                'wrong-threshold-profile',
                            ),
                        },
                    }),
                ),
        ],
        [
            'wrong contributor index',
            expectedVerifierFailure(
                'contributor roster-position binding',
                /contributor|roster|statement|target contract/iu,
            ),
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            contributorRosterPosition:
                                component.statement.contributorRosterPosition +
                                1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong BGV profile hash',
            expectedVerifierFailure(
                'BGV profile hash binding',
                /BGV profile|profile hash|canonical binding/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        profileHash: lowerHexHash('wrong-bgv-profile'),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong BGV backend profile hash',
            expectedVerifierFailure(
                'BGV backend profile hash binding',
                /BGV backend profile|backend profile|canonical binding/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        rustBgvBackendProfileHash: lowerHexHash(
                            'wrong-bgv-backend-profile',
                        ),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong public key root',
            expectedVerifierFailure(
                'BGV public-key root binding',
                /public key|BGV public key|collective public key|canonical binding/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bgvPublicKeyRoot: lowerHexHash('wrong-bgv-key'),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong aggregate input layout hash',
            expectedVerifierFailure(
                'encrypted aggregate input layout binding',
                /layout|profile binding|target contract|statement/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    bridgeEncryption,
                    setupPackageWithCanonicalHash({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            encryptedAggregateInputLayoutHash:
                                lowerHexHash('wrong-layout'),
                        },
                    }),
                ),
        ],
        [
            'scalar-only encoded share layout',
            expectedVerifierFailure(
                'encoded share layout binding',
                /encoded share|layout|statement|target contract/iu,
            ),
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            encodedShareVectorLayoutHash: lowerHexHash(
                                'scalar-only-encoded-share-layout',
                            ),
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'permuted one-hot score buckets',
            expectedVerifierFailure(
                'ballot score encoding profile binding',
                /score|one-hot|profile|target contract|statement/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    bridgeEncryption,
                    setupPackageWithCanonicalHash({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            ballotScoreEncodingProfileHash: lowerHexHash(
                                'permuted-one-hot-score-buckets',
                            ),
                        },
                    }),
                ),
        ],
        [
            'missing score bucket in aggregate layout',
            expectedVerifierFailure(
                'encoded aggregate layout binding',
                /aggregate layout|score|profile|target contract|statement/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    bridgeEncryption,
                    setupPackageWithCanonicalHash({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            encodedAggregateLayoutHash: lowerHexHash(
                                'missing-score-bucket-aggregate-layout',
                            ),
                        },
                    }),
                ),
        ],
        [
            'wrong top-k evaluator input layout',
            expectedVerifierFailure(
                'top-k evaluator layout binding',
                /top-k|evaluator|layout|profile|target contract|bridge proof statement/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    bridgeEncryption,
                    setupPackageWithCanonicalHash({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            topKEvaluatorInputLayoutHash: lowerHexHash(
                                'wrong-top-k-evaluator-input-layout',
                            ),
                        },
                    }),
                ),
        ],
        [
            'wrong encrypted aggregate input root',
            expectedVerifierFailure(
                'encrypted aggregate input root binding',
                /encrypted aggregate input root|encryptedAggregateInputRoot/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        encryptedAggregateInputRoot: lowerHexHash(
                            'wrong-encrypted-aggregate-input-root',
                        ),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong encrypted aggregate reconstruction hash',
            expectedVerifierFailure(
                'encrypted aggregate reconstruction binding',
                /reconstruction|profile|target contract|statement/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    bridgeEncryption,
                    setupPackageWithCanonicalHash({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            encryptedAggregateReconstructionHash: lowerHexHash(
                                'wrong-encrypted-aggregate-reconstruction',
                            ),
                        },
                    }),
                ),
        ],
        [
            'wrong VotingClosed hash',
            expectedVerifierFailure(
                'voting-closed board context binding',
                /VotingClosed|board|post-close|context|statement/iu,
            ),
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            votingClosedBoardHeadHash:
                                lowerHexHash('wrong-board-head'),
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong selected ballot set hash',
            expectedVerifierFailure(
                'selected ballot-set binding',
                /ballot set|ballotSet|statement|target contract/iu,
            ),
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            ballotSetHash: lowerHexHash('wrong-ballot-set'),
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'pending bridge record selected',
            expectedVerifierFailure(
                'pending bridge proof selection refusal',
                /pending|proof-valid|BridgeProofRelationChecked|contribution/iu,
            ),
            () => {
                const pendingContribution: AggregateContribution = {
                    ...input.contribution.aggregateContribution,
                    bridgeProofRecord: {
                        ...input.contribution.aggregateContribution
                            .bridgeProofRecord,
                        bridgeProofVerificationStatus:
                            'BridgeProofBackendPending',
                    },
                };

                return selectFirstValidAggregateContributions({
                    aggregateContributionQuorum: 1,
                    contributions: [pendingContribution],
                    currentRecoveryEpochMap: currentRecoveryEpochMap([
                        pendingContribution,
                    ]),
                    expectedAggregateSelectionPolicyHash:
                        input.aggregateSelectionPolicyHash,
                    requiredPostVotingClosedContextHash:
                        pendingContribution.postVotingClosedContextHash,
                });
            },
        ],
        [
            'sampled-only bridge evidence accepted',
            expectedVerifierFailure(
                'sampled-only bridge proof refusal',
                /checked status|verifier-checked|bridge encryption status|real shared-witness|pending|sampled|BridgeProofRelationChecked/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bridgeProofVerificationStatus:
                            'BridgeProofBackendPending',
                    },
                    input.setupPackage,
                ),
        ],
        [
            'witness disclosure flag present',
            expectedVerifierFailure(
                'public witness-field refusal',
                /witness|forbidden|private|public artifact|public field/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bgvPlaintext: [1, 2, 3],
                    },
                    input.setupPackage,
                ),
        ],
        [
            'mixed NTT coefficient-domain bridge object',
            expectedVerifierFailure(
                'coefficient-domain ciphertext convention refusal',
                /basis|coefficient|ciphertext|data basis|canonical/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        basisId: 'QDataNtt',
                    },
                    input.setupPackage,
                ),
        ],
    ];

    return checks.map(([check, expectation, action]) => {
        const failureReason = assertFailure(action, expectation);

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    });
};

export const runSentinelNegativeChecks = (input: {
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly contribution: ContributionBuild;
    readonly heParamHash: ProtocolHash;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const base = {
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
        suite: 'sentinel' as const,
    };
    const verifyMutatedProof = (
        check: string,
        expectation: FailureExpectation,
        proofMutator: (proof: Record<string, unknown>) => void,
    ): NegativeCheck => {
        const mutatedBridge = bridgeWithMutatedProof(
            input.contribution.bridgeEncryption,
            proofMutator,
        );
        const failureReason = assertFailure(
            () =>
                input.kernel.verifyAggregateBridgeEncryption({
                    aggregateDerivationComponent:
                        input.contribution.aggregateDerivationComponent,
                    aggregateSelectionPolicyHash:
                        input.aggregateSelectionPolicyHash,
                    bridgeEncryption: mutatedBridge,
                    bridgeWitnessPrivacyProfileHash:
                        input.bridgeWitnessPrivacyProfileHash,
                    heParamHash: input.heParamHash,
                    setupPackage: input.setupPackage,
                }),
            expectation,
        );

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    };
    const verifyMutatedPublicInput = (
        check: string,
        expectation: FailureExpectation,
        mutation: {
            readonly aggregateDerivationComponent?: unknown;
            readonly bridgeEncryption?: unknown;
            readonly setupPackage?: unknown;
        },
    ): NegativeCheck => {
        const failureReason = assertFailure(
            () =>
                input.kernel.verifyAggregateBridgeEncryption({
                    aggregateDerivationComponent:
                        mutation.aggregateDerivationComponent ??
                        input.contribution.aggregateDerivationComponent,
                    aggregateSelectionPolicyHash:
                        input.aggregateSelectionPolicyHash,
                    bridgeEncryption:
                        mutation.bridgeEncryption ??
                        input.contribution.bridgeEncryption,
                    bridgeWitnessPrivacyProfileHash:
                        input.bridgeWitnessPrivacyProfileHash,
                    heParamHash: input.heParamHash,
                    setupPackage: mutation.setupPackage ?? input.setupPackage,
                }),
            expectation,
        );

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    };
    const mutateSharedWitnessResponse =
        (fieldName: string): ((proof: Record<string, unknown>) => void) =>
        (proof) => {
            const sharedProof = proof.bridgeSharedWitnessProof as {
                readonly checks: Record<string, unknown>[];
            };
            sharedProof.checks[0][fieldName] = mutateLastHexDigit(
                sharedProof.checks[0][fieldName],
            );
        };
    const mutateFirstBgvBoundExpansionCommitment = (
        proof: Record<string, unknown>,
    ): void => {
        const sharedProof = proof.bridgeSharedWitnessProof as {
            readonly checks: Record<string, unknown>[];
        };
        const firstCheck = sharedProof.checks[0];
        const bgvRandomnessBoundCommitment =
            firstCheck.bgvRandomnessBoundCommitment as Record<string, unknown>;
        const supportModuli =
            bgvRandomnessBoundCommitment.supportModuli as readonly number[];
        const randomizerCommitmentsByModulus =
            bgvRandomnessBoundCommitment.randomizerExpansionCommitmentsByModulus as number[][];
        const firstModulus = supportModuli[0];
        const firstCommitment = randomizerCommitmentsByModulus[0][0];
        randomizerCommitmentsByModulus[0][0] =
            (firstCommitment + 1) % firstModulus;
        firstCheck.bgvRandomnessBoundCommitmentHash =
            bgvRandomnessBoundCommitmentHash(bgvRandomnessBoundCommitment);
    };
    const checks = [
        verifyMutatedProof(
            'wrong aggregate derivation opening',
            expectedVerifierFailure(
                'aggregate opening response commitment',
                /aggregate relation commitment|shared-witness|aggregate derivation|opening/iu,
            ),
            mutateSharedWitnessResponse('aggregateOpeningResponseHex'),
        ),
        verifyMutatedProof(
            'out-of-bound shared witness response',
            expectedVerifierFailure(
                'shared-witness response bound check',
                /shared-witness|response|bound|signed i256/iu,
            ),
            (proof) => {
                const sharedProof = proof.bridgeSharedWitnessProof as {
                    readonly checks: Record<string, unknown>[];
                };
                sharedProof.checks[0].aggregateShareResponseHex =
                    mutateFirstSignedI256ResponseOutOfBound(
                        sharedProof.checks[0].aggregateShareResponseHex,
                    );
            },
        ),
        verifyMutatedProof(
            'wrong reduced coordinate',
            expectedVerifierFailure(
                'reduced-coordinate response commitment',
                /aggregate relation commitment|batch encoding|shared-witness|reduced/iu,
            ),
            mutateSharedWitnessResponse('aggregateReducedResponseHex'),
        ),
        verifyMutatedProof(
            'wrong quotient',
            expectedVerifierFailure(
                'quotient response commitment',
                /aggregate relation commitment|shared-witness|quotient/iu,
            ),
            mutateSharedWitnessResponse('aggregateQuotientResponseHex'),
        ),
        verifyMutatedPublicInput(
            'wrong quotient bound',
            expectedVerifierFailure(
                'aggregate quotient bound certificate',
                /quotient|bound|aggregate derivation|proof statement|no-wraparound/iu,
            ),
            {
                aggregateDerivationComponent: {
                    ...input.contribution.aggregateDerivationComponent,
                    shareCommitmentMessageBoundCert: {
                        ...input.contribution.aggregateDerivationComponent
                            .shareCommitmentMessageBoundCert,
                        quotientBoundForAggregateReduction:
                            input.contribution.aggregateDerivationComponent
                                .shareCommitmentMessageBoundCert
                                .quotientBoundForAggregateReduction + 1,
                    },
                },
            },
        ),
        verifyMutatedProof(
            'wrong encoded coordinate order',
            expectedVerifierFailure(
                'aggregate share response commitment',
                /aggregate relation commitment|shared-witness|share/iu,
            ),
            mutateSharedWitnessResponse('aggregateShareResponseHex'),
        ),
        verifyMutatedProof(
            'wrong slot layout',
            expectedVerifierFailure(
                'bridge layout hash binding',
                /layout|statement|shared-witness|bridge proof/iu,
            ),
            (proof) => {
                const statement = proof.bridgeProofStatement as Record<
                    string,
                    unknown
                >;
                statement.bridgeLayoutHash = lowerHexHash('wrong-slot-layout');
            },
        ),
        verifyMutatedProof(
            'wrong batch encoding',
            expectedVerifierFailure(
                'batch coefficient response commitment',
                /batch|shared-witness|commitment|encoding/iu,
            ),
            mutateSharedWitnessResponse('batchCoefficientResponseHex'),
        ),
        verifyMutatedProof(
            'wrong plaintext polynomial',
            expectedVerifierFailure(
                'BGV plaintext root binding',
                /plaintext|BGV|bridge proof|shared-witness/iu,
            ),
            (proof) => {
                proof.plaintextRoot = lowerHexHash(
                    'wrong-plaintext-polynomial',
                );
            },
        ),
        verifyMutatedPublicInput(
            'wrong RNS limb',
            expectedVerifierFailure(
                'bridge encryption canonical bytes',
                /canonical|RNS|ciphertext|bridge encryption|hash/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    canonicalBytesHex: mutateFirstCanonicalBgvCiphertextResidue(
                        input.contribution.bridgeEncryption.canonicalBytesHex,
                    ),
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong ciphertext component',
            expectedVerifierFailure(
                'BGV ciphertext root binding',
                /ciphertext|BGV|bridge encryption|hash/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    ciphertextRoot: lowerHexHash('wrong-ciphertext-component'),
                },
            },
        ),
        verifyMutatedProof(
            'wrong encryption randomness',
            expectedVerifierFailure(
                'cipher randomizer response commitment',
                /cipher|random|shared-witness|commitment/iu,
            ),
            mutateSharedWitnessResponse('cipherRandomizerResponseHex'),
        ),
        verifyMutatedProof(
            'wrong noise bound',
            expectedVerifierFailure(
                'bounded perturbation response commitment',
                /bounded|perturbation|noise|shared-witness|commitment/iu,
            ),
            mutateSharedWitnessResponse('boundedPerturbationZeroResponseHex'),
        ),
        verifyMutatedProof(
            'wrong BGV boundedness commitment hash',
            expectedVerifierFailure(
                'BGV boundedness commitment hash',
                /BGV|boundedness|commitment|hash/iu,
            ),
            (proof) => {
                const sharedProof = proof.bridgeSharedWitnessProof as {
                    readonly checks: Record<string, unknown>[];
                };
                sharedProof.checks[0].bgvRandomnessBoundCommitmentHash =
                    lowerHexHash('wrong-bgv-boundedness-commitment-hash');
            },
        ),
        verifyMutatedProof(
            'wrong BGV boundedness support polynomial',
            expectedVerifierFailure(
                'BGV boundedness support polynomial',
                /BGV boundedness support polynomial|cipher-randomizer/iu,
            ),
            mutateFirstBgvBoundExpansionCommitment,
        ),
        verifyMutatedPublicInput(
            'wrong shared-witness proof hash',
            expectedVerifierFailure(
                'shared-witness proof hash binding',
                /shared-witness|proof hash|hash/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    bridgeSharedWitnessProofHash: lowerHexHash(
                        'wrong-shared-witness-proof-hash',
                    ),
                },
            },
        ),
        verifyMutatedProof(
            'wrong shared-witness ZK status evidence',
            expectedVerifierFailure(
                'shared-witness zero-knowledge status evidence',
                /zero-knowledge|ZK|status|shared-witness|hash/iu,
            ),
            (proof) => {
                const statusEvidence =
                    proof.sharedWitnessZeroKnowledgeStatusEvidence as Record<
                        string,
                        unknown
                    >;
                statusEvidence.simulatorProofChecked = false;
            },
        ),
        verifyMutatedPublicInput(
            'wrong shared-witness ZK status hash',
            expectedVerifierFailure(
                'shared-witness zero-knowledge status hash',
                /zero-knowledge|ZK|status|shared-witness|hash/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    sharedWitnessZeroKnowledgeStatusHash: lowerHexHash(
                        'wrong-shared-witness-zk-status-hash',
                    ),
                },
            },
        ),
        verifyMutatedProof(
            'wrong BGV boundedness status evidence',
            expectedVerifierFailure(
                'BGV boundedness status evidence',
                /BGV|boundedness|randomness|status|hash/iu,
            ),
            (proof) => {
                const statusEvidence =
                    proof.bgvRandomnessBoundProofStatusEvidence as Record<
                        string,
                        unknown
                    >;
                statusEvidence.verifierBoundednessProofChecked = false;
            },
        ),
        verifyMutatedPublicInput(
            'wrong BGV boundedness status hash',
            expectedVerifierFailure(
                'BGV boundedness status hash',
                /BGV|boundedness|randomness|status|hash/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    bgvRandomnessBoundProofStatusHash: lowerHexHash(
                        'wrong-bgv-boundedness-status-hash',
                    ),
                },
            },
        ),
        verifyMutatedProof(
            'unsupported BGV boundedness proof bytes',
            expectedVerifierFailure(
                'unsupported BGV boundedness proof bytes',
                /unsupported field|BGV|boundedness|proof bytes/iu,
            ),
            (proof) => {
                proof.bgvRandomnessBoundProofBytesHex = '00';
            },
        ),
        verifyMutatedPublicInput(
            'wrong collective public key',
            expectedVerifierFailure(
                'collective public key root binding',
                /collective public key|setup|root|hash/iu,
            ),
            {
                setupPackage: {
                    ...input.setupPackage,
                    collectivePublicKey: {
                        ...(input.setupPackage.collectivePublicKey as Record<
                            string,
                            unknown
                        >),
                        collectivePublicKeyRoot: lowerHexHash(
                            'wrong-collective-public-key',
                        ),
                    },
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong collective public key coefficient material',
            expectedVerifierFailure(
                'collective public key coefficient root binding',
                /collective public key|coefficient|setup|root|hash/iu,
            ),
            {
                setupPackage: {
                    ...input.setupPackage,
                    collectivePublicKey: {
                        ...(input.setupPackage.collectivePublicKey as Record<
                            string,
                            unknown
                        >),
                        collectivePublicKeyCoefficientRoot: lowerHexHash(
                            'wrong-collective-public-key-coefficients',
                        ),
                    },
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong setup root',
            expectedVerifierFailure(
                'setup package root binding',
                /setup|root|hash|package/iu,
            ),
            {
                setupPackage: {
                    ...input.setupPackage,
                    setupPackageHash: lowerHexHash('wrong-setup-package'),
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong board context',
            expectedVerifierFailure(
                'board context hash binding',
                /board|context|hash|statement/iu,
            ),
            {
                aggregateDerivationComponent: {
                    ...input.contribution.aggregateDerivationComponent,
                    statement: {
                        ...input.contribution.aggregateDerivationComponent
                            .statement,
                        votingClosedBoardHeadHash: lowerHexHash(
                            'wrong-board-context',
                        ),
                    },
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong action context',
            expectedVerifierFailure(
                'action context hash binding',
                /action|context|hash|statement/iu,
            ),
            {
                aggregateDerivationComponent: {
                    ...input.contribution.aggregateDerivationComponent,
                    statement: {
                        ...input.contribution.aggregateDerivationComponent
                            .statement,
                        contributorActionContextHash: lowerHexHash(
                            'wrong-action-context',
                        ),
                    },
                },
            },
        ),
        verifyMutatedProof(
            'same aggregate derivation subproof but different BGV plaintext',
            expectedVerifierFailure(
                'cross-relation plaintext binding',
                /plaintext|aggregate relation|shared-witness|BGV/iu,
            ),
            (proof) => {
                proof.plaintextRoot = lowerHexHash('wrong-plaintext-root');
            },
        ),
        verifyMutatedProof(
            'same BGV ciphertext but different aggregate derivation commitment',
            expectedVerifierFailure(
                'cross-relation commitment binding',
                /aggregate relation|commitment|shared-witness|BGV/iu,
            ),
            (proof) => {
                proof.aggregateRelationCommitmentHash = lowerHexHash(
                    'wrong-aggregate-relation',
                );
            },
        ),
        verifyMutatedProof(
            'forged BridgeProofRelationChecked',
            expectedVerifierFailure(
                'bridge relation proof structure',
                /shared-witness|bridge proof|relation|structure|objectVersion/iu,
            ),
            (proof) => {
                proof.bridgeSharedWitnessProof = {
                    objectType: 'AggregateBridgeSharedWitnessProof',
                };
            },
        ),
        verifyMutatedProof(
            'witness field included in public artifact',
            expectedVerifierFailure(
                'public witness field rejection',
                /witness|forbidden|public artifact|structure/iu,
            ),
            (proof) => {
                proof.aggregateIntegerShareVector = [1, 2, 3];
            },
        ),
    ];

    return checks;
};
