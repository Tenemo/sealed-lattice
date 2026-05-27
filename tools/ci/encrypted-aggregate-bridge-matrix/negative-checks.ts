import { currentRecoveryEpochMap } from './fixtures.js';
import {
    lowerHexDigest,
    type ContributionBuild,
    type NegativeCheck,
    type TranscriptCoreKernel,
    type Variant,
} from './shared.js';

import {
    canonicalJson,
    deriveProtocolDigest,
} from '#packages/crypto/src/index';
import { selectFirstValidAggregateContributions } from '#packages/protocol/src/ballot-privacy/index';
import type {
    AggregateContribution,
    ProtocolDigest,
} from '#packages/types/src/index';

type FailureExpectation = {
    readonly description: string;
    readonly pattern: RegExp;
};

type CheapNegativeCase = readonly [
    check: string,
    expectation: FailureExpectation,
    action: () => unknown,
];

const expectedVerifierFailure = (
    description: string,
    pattern: RegExp,
): FailureExpectation => ({
    description,
    pattern,
});

const verifierFailureDiagnostics = (failure: {
    readonly refusedObjects?: unknown;
    readonly statusLabels?: unknown;
    readonly unresolvedReason?: unknown;
}): readonly string[] => {
    const diagnostics: string[] = [];
    if (typeof failure.unresolvedReason === 'string') {
        diagnostics.push(failure.unresolvedReason);
    }
    if (Array.isArray(failure.statusLabels)) {
        diagnostics.push(
            ...failure.statusLabels.flatMap((statusLabel) =>
                typeof statusLabel === 'string' ? [statusLabel] : [],
            ),
        );
    }
    if (Array.isArray(failure.refusedObjects)) {
        for (const refusedObject of failure.refusedObjects) {
            if (typeof refusedObject === 'string') {
                diagnostics.push(refusedObject);
            } else if (
                typeof refusedObject === 'object' &&
                refusedObject !== null
            ) {
                const refusal = refusedObject as {
                    readonly code?: unknown;
                    readonly message?: unknown;
                    readonly object?: unknown;
                    readonly path?: unknown;
                };
                for (const value of [
                    refusal.code,
                    refusal.message,
                    refusal.object,
                    refusal.path,
                ]) {
                    if (typeof value === 'string') {
                        diagnostics.push(value);
                    }
                }
            }
        }
    }

    return diagnostics;
};

const assertFailure = (
    action: () => unknown,
    expectation: FailureExpectation,
): string | null => {
    try {
        const result = action();
        if (
            typeof result === 'object' &&
            result !== null &&
            'ok' in result &&
            (result as { readonly ok?: unknown }).ok === false
        ) {
            const failure = result as {
                readonly refusedObjects?: unknown;
                readonly statusLabels?: unknown;
                readonly unresolvedReason?: unknown;
            };
            const diagnostics = verifierFailureDiagnostics(failure);
            if (diagnostics.length === 0) {
                return 'mutation returned ok:false without verifier refusal metadata';
            }
            if (
                diagnostics.some((diagnostic) =>
                    expectation.pattern.test(diagnostic),
                )
            ) {
                return null;
            }

            return `mutation failed with unexpected verifier diagnostic for ${expectation.description}: ${diagnostics.join(' | ')}`;
        }

        return 'mutation unexpectedly passed';
    } catch (error) {
        return `mutation threw a harness exception: ${
            error instanceof Error ? error.message : String(error)
        }`;
    }
};

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

const bridgeSharedWitnessProofDigest = (
    bridgeSharedWitnessProof: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        bridgeSharedWitnessProof,
        purpose:
            'sealed-lattice-aggregate-bridge-shared-witness-proof-digest-v1',
    });

const bgvRandomnessBoundProofStatusDigest = (
    bgvRandomnessBoundProofStatusEvidence: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        bgvRandomnessBoundProofStatusEvidence,
        purpose:
            'sealed-lattice-aggregate-bridge-bgv-randomness-bound-status-v1',
    });

const bgvRandomnessBoundCommitmentDigest = (
    bgvRandomnessBoundCommitment: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        bgvRandomnessBoundCommitment,
        purpose:
            'sealed-lattice-aggregate-bridge-bgv-randomness-bound-commitment-v1',
    });

const sharedWitnessZeroKnowledgeStatusDigest = (
    sharedWitnessZeroKnowledgeStatusEvidence: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        sharedWitnessZeroKnowledgeStatusEvidence,
        purpose:
            'sealed-lattice-aggregate-bridge-shared-witness-zero-knowledge-status-v1',
    });

const setupPackageWithCanonicalDigest = (
    setupPackage: Record<string, unknown>,
): Record<string, unknown> => {
    const digestInput = structuredClone(setupPackage);
    delete digestInput.setupPackageDigest;

    return {
        ...setupPackage,
        setupPackageDigest: deriveProtocolDigest(
            'BGVPassiveSetupPackageDigest',
            digestInput,
        ),
    };
};

const refreshBridgeProofSubproofDigests = (
    proof: Record<string, unknown>,
): void => {
    if (
        typeof proof.bridgeSharedWitnessProof === 'object' &&
        proof.bridgeSharedWitnessProof !== null
    ) {
        proof.bridgeSharedWitnessProofDigest = bridgeSharedWitnessProofDigest(
            proof.bridgeSharedWitnessProof,
        );
    }
    if (typeof proof.bridgeSharedWitnessProofDigest === 'string') {
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
            ).bridgeSharedWitnessProofDigest =
                proof.bridgeSharedWitnessProofDigest;
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
            ).bridgeSharedWitnessProofDigest =
                proof.bridgeSharedWitnessProofDigest;
        }
    }
    if (
        typeof proof.sharedWitnessZeroKnowledgeStatusEvidence === 'object' &&
        proof.sharedWitnessZeroKnowledgeStatusEvidence !== null
    ) {
        proof.sharedWitnessZeroKnowledgeStatusDigest =
            sharedWitnessZeroKnowledgeStatusDigest(
                proof.sharedWitnessZeroKnowledgeStatusEvidence,
            );
    }
    if (
        typeof proof.bgvRandomnessBoundProofStatusEvidence === 'object' &&
        proof.bgvRandomnessBoundProofStatusEvidence !== null
    ) {
        proof.bgvRandomnessBoundProofStatusDigest =
            bgvRandomnessBoundProofStatusDigest(
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
    refreshBridgeProofSubproofDigests(proof);
    const bridgeProofBytesHex = Buffer.from(
        canonicalJson(proof),
        'utf8',
    ).toString('hex');
    const bridgeProofBytesDigest = deriveProtocolDigest('ProofBytesDigest', {
        proofBytesHex: bridgeProofBytesHex,
        purpose: 'sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1',
    });

    return {
        ...bridgeEncryption,
        bridgeProofBytesHex,
        bridgeProofBytesDigest,
        ...(typeof proof.bridgeSharedWitnessProofDigest === 'string'
            ? {
                  bridgeSharedWitnessProofDigest:
                      proof.bridgeSharedWitnessProofDigest,
              }
            : {}),
        ...(typeof proof.sharedWitnessZeroKnowledgeStatusDigest === 'string'
            ? {
                  sharedWitnessZeroKnowledgeStatusDigest:
                      proof.sharedWitnessZeroKnowledgeStatusDigest,
              }
            : {}),
        ...(typeof proof.bgvRandomnessBoundProofStatusDigest === 'string'
            ? {
                  bgvRandomnessBoundProofStatusDigest:
                      proof.bgvRandomnessBoundProofStatusDigest,
              }
            : {}),
        bridgeProofRoot: deriveProtocolDigest('BridgeProofRecordDigest', {
            aggregateDerivationComponentDigest:
                bridgeEncryption.aggregateDerivationComponentDigest,
            aggregateDerivationStatementDigest:
                bridgeEncryption.aggregateDerivationStatementDigest,
            bgvPublicKeyRoot: bridgeEncryption.bgvPublicKeyRoot,
            bridgeProofProfileDigest: bridgeEncryption.bridgeProofProfileDigest,
            bridgeProofStatementDigest:
                bridgeEncryption.bridgeProofStatementDigest,
            collectivePublicKeyRoot: bridgeEncryption.collectivePublicKeyRoot,
            encryptedAggregateShareCiphertextRoot:
                bridgeEncryption.encryptedAggregateShareCiphertextRoot,
            ...(typeof proof.bridgeSharedWitnessProofDigest === 'string'
                ? {
                      bridgeSharedWitnessProofDigest:
                          proof.bridgeSharedWitnessProofDigest,
                  }
                : {}),
            ...(typeof proof.sharedWitnessZeroKnowledgeStatusDigest === 'string'
                ? {
                      sharedWitnessZeroKnowledgeStatusDigest:
                          proof.sharedWitnessZeroKnowledgeStatusDigest,
                  }
                : {}),
            ...(typeof proof.bgvRandomnessBoundProofStatusDigest === 'string'
                ? {
                      bgvRandomnessBoundProofStatusDigest:
                          proof.bgvRandomnessBoundProofStatusDigest,
                  }
                : {}),
            proofBytesDigest: bridgeProofBytesDigest,
            purpose: 'sealed-lattice-aggregate-bridge-encryption-proof-root-v1',
        }),
    };
};

export const runCheapNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly contribution: ContributionBuild;
    readonly heParamDigest: ProtocolDigest;
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
        aggregateSelectionPolicyDigest = input.aggregateSelectionPolicyDigest,
    ): unknown =>
        input.kernel.verifyAggregateBridgeEncryption({
            aggregateDerivationComponent,
            aggregateSelectionPolicyDigest,
            bridgeEncryption,
            bridgeWitnessPrivacyProfileDigest:
                input.bridgeWitnessPrivacyProfileDigest,
            heParamDigest: input.heParamDigest,
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
                    setupPackageWithCanonicalDigest({
                        ...input.setupPackage,
                        setupInputs: {
                            ...(input.setupPackage.setupInputs as Record<
                                string,
                                unknown
                            >),
                            thresholdProfileDigest: lowerHexDigest(
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
                'BGV profile digest binding',
                /BGV profile|profile digest|canonical binding/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        profileDigest: lowerHexDigest('wrong-bgv-profile'),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong BGV backend profile hash',
            expectedVerifierFailure(
                'BGV backend profile digest binding',
                /BGV backend profile|backend profile|canonical binding/iu,
            ),
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        rustBgvBackendProfileDigest: lowerHexDigest(
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
                        bgvPublicKeyRoot: lowerHexDigest('wrong-bgv-key'),
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
                    setupPackageWithCanonicalDigest({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            encryptedAggregateInputLayoutDigest:
                                lowerHexDigest('wrong-layout'),
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
                            encodedShareVectorLayoutDigest: lowerHexDigest(
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
                    setupPackageWithCanonicalDigest({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            ballotScoreEncodingProfileDigest: lowerHexDigest(
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
                    setupPackageWithCanonicalDigest({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            encodedAggregateLayoutDigest: lowerHexDigest(
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
                    setupPackageWithCanonicalDigest({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            topKEvaluatorInputLayoutDigest: lowerHexDigest(
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
                        encryptedAggregateInputRoot: lowerHexDigest(
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
                    setupPackageWithCanonicalDigest({
                        ...input.setupPackage,
                        profileBindings: {
                            ...(input.setupPackage.profileBindings as Record<
                                string,
                                unknown
                            >),
                            encryptedAggregateReconstructionDigest:
                                lowerHexDigest(
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
                            votingClosedBoardHeadDigest:
                                lowerHexDigest('wrong-board-head'),
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
                            ballotSetDigest: lowerHexDigest('wrong-ballot-set'),
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
                    expectedAggregateSelectionPolicyDigest:
                        input.aggregateSelectionPolicyDigest,
                    requiredPostVotingClosedContextDigest:
                        pendingContribution.postVotingClosedContextDigest,
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
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly contribution: ContributionBuild;
    readonly heParamDigest: ProtocolDigest;
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
                    aggregateSelectionPolicyDigest:
                        input.aggregateSelectionPolicyDigest,
                    bridgeEncryption: mutatedBridge,
                    bridgeWitnessPrivacyProfileDigest:
                        input.bridgeWitnessPrivacyProfileDigest,
                    heParamDigest: input.heParamDigest,
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
                    aggregateSelectionPolicyDigest:
                        input.aggregateSelectionPolicyDigest,
                    bridgeEncryption:
                        mutation.bridgeEncryption ??
                        input.contribution.bridgeEncryption,
                    bridgeWitnessPrivacyProfileDigest:
                        input.bridgeWitnessPrivacyProfileDigest,
                    heParamDigest: input.heParamDigest,
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
        firstCheck.bgvRandomnessBoundCommitmentDigest =
            bgvRandomnessBoundCommitmentDigest(bgvRandomnessBoundCommitment);
    };
    const checks = [
        verifyMutatedProof(
            'wrong M6 opening',
            expectedVerifierFailure(
                'aggregate opening response commitment',
                /aggregate relation commitment|shared-witness|M6|opening/iu,
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
                'bridge layout digest binding',
                /layout|statement|shared-witness|bridge proof/iu,
            ),
            (proof) => {
                const statement = proof.bridgeProofStatement as Record<
                    string,
                    unknown
                >;
                statement.bridgeLayoutDigest =
                    lowerHexDigest('wrong-slot-layout');
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
                proof.plaintextRoot = lowerHexDigest(
                    'wrong-plaintext-polynomial',
                );
            },
        ),
        verifyMutatedPublicInput(
            'wrong RNS limb',
            expectedVerifierFailure(
                'bridge encryption canonical bytes',
                /canonical|RNS|ciphertext|bridge encryption|digest/iu,
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
                /ciphertext|BGV|bridge encryption|digest/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    ciphertextRoot: lowerHexDigest(
                        'wrong-ciphertext-component',
                    ),
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
            'wrong BGV boundedness commitment digest',
            expectedVerifierFailure(
                'BGV boundedness commitment digest',
                /BGV|boundedness|commitment|digest/iu,
            ),
            (proof) => {
                const sharedProof = proof.bridgeSharedWitnessProof as {
                    readonly checks: Record<string, unknown>[];
                };
                sharedProof.checks[0].bgvRandomnessBoundCommitmentDigest =
                    lowerHexDigest('wrong-bgv-boundedness-commitment-digest');
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
            'wrong shared-witness proof digest',
            expectedVerifierFailure(
                'shared-witness proof digest binding',
                /shared-witness|proof digest|digest/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    bridgeSharedWitnessProofDigest: lowerHexDigest(
                        'wrong-shared-witness-proof-digest',
                    ),
                },
            },
        ),
        verifyMutatedProof(
            'wrong shared-witness ZK status evidence',
            expectedVerifierFailure(
                'shared-witness zero-knowledge status evidence',
                /zero-knowledge|ZK|status|shared-witness|digest/iu,
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
            'wrong shared-witness ZK status digest',
            expectedVerifierFailure(
                'shared-witness zero-knowledge status digest',
                /zero-knowledge|ZK|status|shared-witness|digest/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    sharedWitnessZeroKnowledgeStatusDigest: lowerHexDigest(
                        'wrong-shared-witness-zk-status-digest',
                    ),
                },
            },
        ),
        verifyMutatedProof(
            'wrong BGV boundedness status evidence',
            expectedVerifierFailure(
                'BGV boundedness status evidence',
                /BGV|boundedness|randomness|status|digest/iu,
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
            'wrong BGV boundedness status digest',
            expectedVerifierFailure(
                'BGV boundedness status digest',
                /BGV|boundedness|randomness|status|digest/iu,
            ),
            {
                bridgeEncryption: {
                    ...input.contribution.bridgeEncryption,
                    bgvRandomnessBoundProofStatusDigest: lowerHexDigest(
                        'wrong-bgv-boundedness-status-digest',
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
                /collective public key|setup|root|digest/iu,
            ),
            {
                setupPackage: {
                    ...input.setupPackage,
                    collectivePublicKey: {
                        ...(input.setupPackage.collectivePublicKey as Record<
                            string,
                            unknown
                        >),
                        collectivePublicKeyRoot: lowerHexDigest(
                            'wrong-collective-public-key',
                        ),
                    },
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong setup root',
            expectedVerifierFailure(
                'setup package root binding',
                /setup|root|digest|package/iu,
            ),
            {
                setupPackage: {
                    ...input.setupPackage,
                    setupPackageDigest: lowerHexDigest('wrong-setup-package'),
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong board context',
            expectedVerifierFailure(
                'board context digest binding',
                /board|context|digest|statement/iu,
            ),
            {
                aggregateDerivationComponent: {
                    ...input.contribution.aggregateDerivationComponent,
                    statement: {
                        ...input.contribution.aggregateDerivationComponent
                            .statement,
                        votingClosedBoardHeadDigest: lowerHexDigest(
                            'wrong-board-context',
                        ),
                    },
                },
            },
        ),
        verifyMutatedPublicInput(
            'wrong action context',
            expectedVerifierFailure(
                'action context digest binding',
                /action|context|digest|statement/iu,
            ),
            {
                aggregateDerivationComponent: {
                    ...input.contribution.aggregateDerivationComponent,
                    statement: {
                        ...input.contribution.aggregateDerivationComponent
                            .statement,
                        contributorActionContextDigest: lowerHexDigest(
                            'wrong-action-context',
                        ),
                    },
                },
            },
        ),
        verifyMutatedProof(
            'same M6 subproof but different BGV plaintext',
            expectedVerifierFailure(
                'cross-relation plaintext binding',
                /plaintext|aggregate relation|shared-witness|BGV/iu,
            ),
            (proof) => {
                proof.plaintextRoot = lowerHexDigest('wrong-plaintext-root');
            },
        ),
        verifyMutatedProof(
            'same BGV ciphertext but different M6 commitment',
            expectedVerifierFailure(
                'cross-relation commitment binding',
                /aggregate relation|commitment|shared-witness|BGV/iu,
            ),
            (proof) => {
                proof.aggregateRelationCommitmentDigest = lowerHexDigest(
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

export const runSelectionNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly selectedContributionRecords: readonly AggregateContribution[];
    readonly trusteeAggregateThreshold: number;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const remainingContributions = input.selectedContributionRecords.slice(1);
    const failureReason = assertFailure(
        () =>
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: input.trusteeAggregateThreshold,
                contributions: remainingContributions,
                currentRecoveryEpochMap: currentRecoveryEpochMap(
                    remainingContributions,
                ),
                expectedAggregateSelectionPolicyDigest:
                    input.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    input.postVotingClosedContextDigest,
            }),
        expectedVerifierFailure(
            'selected contribution quorum refusal',
            /quorum|selected|contribution|valid/iu,
        ),
    );
    const firstContribution = input.selectedContributionRecords[0];
    const staleRecoveryEpochFailureReason = assertFailure(
        () =>
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: input.trusteeAggregateThreshold,
                contributions: input.selectedContributionRecords,
                currentRecoveryEpochMap: {
                    ...currentRecoveryEpochMap(
                        input.selectedContributionRecords,
                    ),
                    [firstContribution.contributorIdentity]: {
                        currentDeviceEpoch: firstContribution.deviceEpoch,
                        currentRecoveryEpoch:
                            firstContribution.recoveryEpoch + 1,
                        signerIdentity: firstContribution.contributorIdentity,
                    },
                },
                expectedAggregateSelectionPolicyDigest:
                    input.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    input.postVotingClosedContextDigest,
            }),
        expectedVerifierFailure(
            'stale recovery epoch refusal',
            /recovery epoch|stale|epoch|current/iu,
        ),
    );
    const clonedDeviceEpochFailureReason = assertFailure(
        () =>
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: input.trusteeAggregateThreshold,
                contributions: input.selectedContributionRecords,
                currentRecoveryEpochMap: {
                    ...currentRecoveryEpochMap(
                        input.selectedContributionRecords,
                    ),
                    [firstContribution.contributorIdentity]: {
                        currentDeviceEpoch: firstContribution.deviceEpoch + 1,
                        currentRecoveryEpoch: firstContribution.recoveryEpoch,
                        signerIdentity: firstContribution.contributorIdentity,
                    },
                },
                expectedAggregateSelectionPolicyDigest:
                    input.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    input.postVotingClosedContextDigest,
            }),
        expectedVerifierFailure(
            'cloned device epoch refusal',
            /device epoch|cloned|epoch|current/iu,
        ),
    );

    return [
        {
            check: 'wrong selected contributor set',
            expectedFailureObserved: failureReason === null,
            failureReason,
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
            suite: 'cheap',
        },
        {
            check: 'stale recovery epoch',
            expectedFailureObserved: staleRecoveryEpochFailureReason === null,
            failureReason: staleRecoveryEpochFailureReason,
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
            suite: 'cheap',
        },
        {
            check: 'cloned device epoch',
            expectedFailureObserved: clonedDeviceEpochFailureReason === null,
            failureReason: clonedDeviceEpochFailureReason,
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
            suite: 'cheap',
        },
    ];
};
