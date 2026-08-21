import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export type JsonPrimitive = boolean | null | number | string;
export type JsonValue =
    | JsonPrimitive
    | readonly JsonValue[]
    | { readonly [fieldName: string]: JsonValue };

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

export const selectedCollectiveSetupSecurityEvidencePath = path.join(
    repositoryRoot,
    'test-vectors/selected-collective-setup-security-evidence.json',
);

const sourcePaths = [
    'Cargo.toml',
    'Cargo.lock',
    'crates/sealed-lattice-kernel/Cargo.toml',
    'crates/sealed-lattice-kernel/src/foundation/hash.rs',
    'crates/sealed-lattice-kernel/src/foundation/schemas.rs',
    'crates/sealed-lattice-kernel/src/foundation/proof_application.rs',
    'crates/sealed-lattice-kernel/src/foundation/suite.rs',
    'crates/sealed-lattice-kernel/src/foundation/selected_suite.rs',
    'crates/sealed-lattice-kernel/src/foundation/authenticated_mailbox.rs',
    'crates/sealed-lattice-kernel/src/foundation/mailbox_gcm.rs',
    'crates/sealed-lattice-kernel/src/foundation/private_randomness.rs',
    'crates/sealed-lattice-kernel/src/foundation/private_randomness/generator_hybrid.rs',
    'crates/sealed-lattice-kernel/src/foundation/state.rs',
    'crates/sealed-lattice-kernel/src/foundation/setup_transcript_runtime.rs',
    'crates/sealed-lattice-kernel/src/hashing/mod.rs',
    'crates/sealed-lattice-kernel/src/bgv/parameters.rs',
    'crates/sealed-lattice-kernel/src/bgv/parameters/root_parameters.rs',
    'crates/sealed-lattice-kernel/src/bgv/key_switch_topology.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/candidate_evidence.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/key_switch.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/noise_recurrence.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/top_k/mod.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/top_k/rotations.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/application_statement.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/profile.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/transcript.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/relation_plan.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/relation_plan/interpreter.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/relation_plan/production_source_witness_oracle.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/selected_accounting.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/selected_profile.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/commitment/mod.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/sampling.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/authority.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/canonical_package.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/finalization.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/generation_authority.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/generation_population.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/generation_relinearization.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/verification_assembly.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/verified_terminals.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/verified_public_randomness.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/vss_qualification.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/collective_setup_security_evidence.rs',
    'tools/ci/selected-collective-setup-security-evidence.ts',
] as const;

const setupProofInventory = [
    ['vssShareLinkage', 0x2110, 10, 10],
    ['aggregateThresholdShare', 0x2111, 10, 10],
    ['sameSecret', 0x1211, 10, 10],
    ['publicKeyShare', 0x1212, 10, 10],
    ['collectivePublicKeyAggregate', 0x1213, 1, 1],
    ['relinearizationRoundOne', 0x1214, 10, 10],
    ['relinearizationRoundOneAggregate', 0x1215, 1, 1],
    ['relinearizationRoundTwo', 0x1216, 10, 10],
    ['galoisKeyShareBatch', 0x1217, 10, 60],
    ['evaluatorKeyAggregate', 0x1218, 1, 7],
] as const;

const setupProofInventoryTotals = setupProofInventory.reduce(
    (totals, [, , physicalCount, logicalCount]) => ({
        physicalProofApplicationCount:
            totals.physicalProofApplicationCount + physicalCount,
        logicalRelationInstanceCount:
            totals.logicalRelationInstanceCount + logicalCount,
    }),
    {
        physicalProofApplicationCount: 0,
        logicalRelationInstanceCount: 0,
    },
);

const exactWitnessJoinIdentifiers = [
    'secretContributionAcrossVssAnchorAndKeyShares',
    'relinearizationEphemeralAcrossBothRounds',
    'frozenRoundOneBeforeRoundTwo',
    'thresholdShareSourcesIntoAggregate',
    'evaluatorSourcesIntoRuntimeKey',
] as const;

const exactSampleCorrelationIdentifiers = [
    'collectivePublicKeyCommonUniform',
    'relinearizationCommonUniformByBlock',
    'relinearizationRuntimeAEqualsRoundOneRightAggregate',
    'relinearizationSecretSquareAndEphemeralJoin',
    'galoisCommonUniformByKeyAndBlock',
    'galoisTransformedSecretJoin',
    'deterministicAggregateViewsAreNotFreshSamples',
] as const;

const exactAbortCaseIdentifiers = [
    'beforeRandomnessReservation',
    'afterIntentBeforeCommitment',
    'missingCommitment',
    'afterCommitmentBeforeReveal',
    'missingOrMismatchedReveal',
    'dealerPayloadOrMailboxRefusal',
    'vssQualificationRefusal',
    'sameSecretProofRefusal',
    'thresholdAggregateRefusal',
    'publicKeyShareRefusal',
    'collectivePublicKeyAggregateRefusal',
    'relinearizationRoundOneRefusal',
    'roundOneAggregateRefusal',
    'galoisBatchRefusal',
    'relinearizationRoundTwoRefusal',
    'evaluatorAggregateRefusal',
    'terminalReservationConflict',
    'checkpointAuthenticationRefusal',
    'storageQuotaOrTransactionRefusal',
    'cancellationAtSafeBoundary',
    'lateOrReplayedMessage',
    'wrongActionOrAttempt',
] as const;

const exactResumeBindingIdentifiers = [
    'suiteIdentity',
    'ceremonyContext',
    'actionContext',
    'participantIdentity',
    'applicationSlot',
    'statementHash',
    'sourceRoots',
    'attemptIdentifier',
    'reservedRandomness',
    'checkpointBoundary',
    'predecessorDigest',
    'canonicalPrefixDigest',
] as const;

const exactHybridGameIdentifiers = [
    'realStaticMaliciousExecution',
    'authenticatedCanonicalTranscript',
    'committedSeedBeforePublicMatrices',
    'extractedCorruptWitnessJoins',
    'jointStructuredSampleReplacement',
    'simulatedHonestSetupProofs',
    'simulatedMailboxViews',
    'idealAcceptedPackageOrSecureAbort',
] as const;

const assumptionNodeIdentifiers = [
    'jointStructuredRlweCircularKdm',
    'shakeQuantumOracle',
    'canonicalHashBinding',
    'signatureUnforgeability',
    'mailboxAuthenticatedEncryption',
    'externalActionAuthorizationAndSelectiveAbort',
] as const;

const unresolvedNodeIdentifiers = [
    'commonConstructionKnowledgeSoundness',
    'commonConstructionQromTransform',
    'commonProofQromComposition',
    'commonConstructionMaskingCorrespondence',
    'setupFamilySimulationComposition',
    'collectiveSetupHybridComposition',
] as const;

const exactConstructionEvidenceImportIdentifiers = [
    'commonConstructionKnowledgeSoundness',
    'commonConstructionQromTransform',
    'commonProofQromComposition',
    'commonConstructionMaskingCorrespondence',
] as const;

const requiredReductionNodeIdentifiers = [
    ...assumptionNodeIdentifiers,
    'productionSampleExposureMapping',
    'productionWitnessJoinMapping',
    'commitRevealScheduleReduction',
    'authenticatedTranscriptReduction',
    'mailboxPrivacyReduction',
    'abortAndResumeStateMapping',
    'jointSetupSampleHybrid',
    'commonConstructionKnowledgeSoundness',
    'commonConstructionQromTransform',
    'commonProofQromComposition',
    'commonConstructionMaskingCorrespondence',
    'setupFamilySimulationComposition',
    'selectedSetupCorrectnessImport',
    'collectiveSetupHybridComposition',
] as const;

const exactResidualLedgerIdentifiers = [
    'ordinaryInvalidAcceptance',
    'qromInvalidAcceptance',
    'honestFailureAndCorrectness',
    'statisticalPrivacyAndLeakage',
] as const;

const sha256 = (payload: string | Uint8Array): string =>
    createHash('sha256').update(payload).digest('hex');

const normalizeSourceAuthorityText = (sourceText: string): string =>
    sourceText.replace(/\r\n?/gu, '\n');

const compareOrdinal = (left: string, right: string): number =>
    left < right ? -1 : left > right ? 1 : 0;

const sortJson = (value: JsonValue): JsonValue => {
    if (Array.isArray(value)) {
        const arrayValue = value as readonly JsonValue[];
        return arrayValue.map((entry) => sortJson(entry));
    }
    if (value !== null && typeof value === 'object') {
        const recordValue = value as Record<string, JsonValue>;
        return Object.fromEntries(
            Object.entries(recordValue)
                .sort(([left], [right]) => compareOrdinal(left, right))
                .map(([fieldName, fieldValue]) => [
                    fieldName,
                    sortJson(fieldValue),
                ]),
        );
    }
    return value;
};

export const canonicalJsonText = (value: JsonValue): string =>
    JSON.stringify(sortJson(value));

export const canonicalJsonSha256 = (value: JsonValue): string =>
    sha256(Buffer.from(canonicalJsonText(value), 'utf8'));

export const parseJsonValue = (text: string): JsonValue =>
    JSON.parse(text) as JsonValue;

const requireRecord = (
    value: JsonValue | undefined,
    description: string,
): Record<string, JsonValue> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`${description} must be an object.`);
    }
    return value as Record<string, JsonValue>;
};

const requireArray = (
    value: JsonValue | undefined,
    description: string,
): JsonValue[] => {
    if (!Array.isArray(value)) {
        throw new Error(`${description} must be an array.`);
    }
    return value as JsonValue[];
};

const requireString = (
    value: JsonValue | undefined,
    description: string,
): string => {
    if (typeof value !== 'string') {
        throw new Error(`${description} must be a string.`);
    }
    return value;
};

const requireInteger = (
    value: JsonValue | undefined,
    description: string,
): number => {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
        throw new Error(`${description} must be a safe integer.`);
    }
    return value;
};

const deriveSourceAuthority = async (
    rootPath: string,
): Promise<readonly JsonValue[]> => {
    if (new Set(sourcePaths).size !== sourcePaths.length) {
        throw new Error(
            'The source-authority path catalog contains a duplicate.',
        );
    }
    return Promise.all(
        sourcePaths.map(async (relativePath) => ({
            relativePath,
            sha256: sha256(
                normalizeSourceAuthorityText(
                    await readFile(path.join(rootPath, relativePath), 'utf8'),
                ),
            ),
        })),
    );
};

const enumerateCorruptionSubsets = (
    participantCount: number,
    corruptionCount: number,
): readonly number[][] => {
    const subsets: number[][] = [];
    const visit = (nextPosition: number, current: number[]): void => {
        if (current.length === corruptionCount) {
            subsets.push([...current]);
            return;
        }
        const remaining = corruptionCount - current.length;
        for (
            let rosterPosition = nextPosition;
            rosterPosition <= participantCount - remaining;
            rosterPosition += 1
        ) {
            current.push(rosterPosition);
            visit(rosterPosition + 1, current);
            current.pop();
        }
    };
    visit(0, []);
    return subsets;
};

const buildGame = (): JsonValue => ({
    securityGoal:
        'Static-malicious collective setup with secure abort for one externally authorized action and an exact accepted public package as the only success output.',
    externalInputs: [
        'canonical suite identity',
        'canonical ceremony context',
        'canonical action definition and action context',
        'fixed ordered roster and participant identities',
        'participant signature and mailbox keys',
        'board policy and state reservations',
    ],
    corruptionModel: {
        kind: 'staticBeforeSetup',
        maximumCorruptionCount: 3,
        exactCorruptionCounts: [0, 1, 2, 3],
        exactSubsetCount: 176,
        exactSubsetsByCorruptionCount: [0, 1, 2, 3].map((corruptionCount) => ({
            corruptionCount,
            subsets: enumerateCorruptionSubsets(10, corruptionCount),
        })),
    },
    adversaryPowers: [
        'controls untrusted transcript and mailbox relays',
        'controls message scheduling and rushing',
        'chooses corrupt participant randomness and witness values',
        'may send malformed, replayed, reordered, or conflicting public and private objects',
        'may abort a corrupt participant at any protocol boundary',
    ],
    terminalOutcomes: [
        {
            identifier: 'secureAbort',
            output: 'typed refusal and public abort location with no malformed or partial accepted setup capability',
        },
        {
            identifier: 'acceptedPublicPackage',
            output: 'the exact canonical public transcript and package hash plus owner-local capabilities issued only by production verification',
        },
    ],
    acceptancePredicate: [
        'all public objects are canonical signed carriers under the exact ceremony and action context',
        'all ten randomness commitments precede all ten accepted reveals and bind the public setup seed',
        'all authenticated VSS deliveries reconcile with ten linkage proofs and ten threshold-share aggregate proofs over eight ordered sharing coordinates',
        'ten same-secret proofs join each VSS degree-zero secret to the same three anchor roots used by every setup-key relation',
        'ten public-key shares and one aggregate proof bind the collective public key',
        'ten relinearization round-one proofs and one aggregate proof are fixed before any round-two statement',
        'ten Galois batch proofs bind sixty logical key relations in the exact six-position catalog',
        'ten relinearization round-two proofs bind the same ephemeral witnesses and frozen round-one aggregate',
        'one evaluator aggregate proof binds the exact one relinearization and six Galois runtime entries',
        'the exact terminal package hash receives the required seven finality and state reservations before production authority can issue owner-local outputs',
    ],
    simulatorInputs: [
        'external inputs',
        'corrupt participant inputs and state',
        'plaintexts addressed to corrupt mailbox recipients',
        'public terminal output',
        'public abort location',
    ],
    simulatorForbiddenInputs: [
        'honest secret contributions',
        'honest VSS shares sent only to honest recipients',
        'honest proof masks and private proof coins',
        'honest retained prover state',
        'honest local storage plaintext',
    ],
});

const buildWitnessJoins = (): JsonValue => [
    {
        identifier: exactWitnessJoinIdentifiers[0],
        participantScope: 'each corrupt trustee',
        requiredFamilySchemaIdentifiers: [
            0x2110, 0x1211, 0x1212, 0x1214, 0x1216, 0x1217,
        ],
        bindings: [
            'eight ordered VSS degree-zero commitment roots',
            'three ordered lattice-anchor commitment roots',
            'one secret contribution shared by the VSS, public-key, relinearization, and Galois relations',
            'all errors and openings explaining every committed public component',
        ],
    },
    {
        identifier: exactWitnessJoinIdentifiers[1],
        participantScope: 'each corrupt trustee and relinearization position',
        requiredFamilySchemaIdentifiers: [0x1214, 0x1216],
        bindings: [
            'one relinearization ephemeral secret across both rounds',
            'round-one left and right roots',
            'round-two source roots and frozen round-one aggregate roots',
        ],
    },
    {
        identifier: exactWitnessJoinIdentifiers[2],
        participantScope: 'complete fixed roster',
        requiredFamilySchemaIdentifiers: [0x1214, 0x1215, 0x1216],
        bindings: [
            'all ten ordered round-one source-root pairs precede the aggregate proof',
            'the round-one aggregate is fixed before any round-two statement',
        ],
    },
    {
        identifier: exactWitnessJoinIdentifiers[3],
        participantScope: 'every dealer, recipient, and sharing coordinate',
        requiredFamilySchemaIdentifiers: [0x2110, 0x2111],
        bindings: [
            'ten verified dealer sources for each of eight ordered sharing coordinates',
            'recipient delivery roots match the public dealer proof roots',
            'aggregate threshold roots bind the complete ordered source list',
        ],
    },
    {
        identifier: exactWitnessJoinIdentifiers[4],
        participantScope: 'complete selected evaluator catalog',
        requiredFamilySchemaIdentifiers: [
            0x1213, 0x1215, 0x1216, 0x1217, 0x1218,
        ],
        bindings: [
            'collective public-key aggregate binds all ten public-key shares',
            'relinearization runtime A is the frozen round-one right aggregate',
            'Galois common A is deterministically regenerated from the public seed',
            'one relinearization and six Galois entries feed the evaluator aggregate in production order',
        ],
    },
];

const buildSampleRelations = (): JsonValue => ({
    exactCounts: {
        sourceRelationCountPerParticipant: 61,
        sourceRelationCountForRoster: 610,
        deterministicDerivedRelationCount: 61,
        completePublicRelationCount: 671,
        finalRuntimeKeyRelationCount: 45,
        commonUniformPolynomialCount: 45,
        generatedComponentViewCount: 724,
        distinctPublicPolynomialCount: 716,
        duplicateComponentViewCount: 8,
    },
    orderedBases: [
        {
            family: 'collectivePublicKey',
            catalogLevel: 22,
            dataPrimeCount: 23,
            specialPrimeCount: 0,
            decompositionBlockCount: 0,
        },
        {
            family: 'relinearization',
            catalogLevel: 22,
            dataPrimeCount: 23,
            specialPrimeCount: 3,
            decompositionBlockCount: 8,
        },
        {
            family: 'galois',
            catalogLevel: 14,
            dataPrimeCount: 15,
            specialPrimeCount: 3,
            decompositionBlockCount: 5,
            keyCount: 3,
        },
        {
            family: 'galois',
            catalogLevel: 18,
            dataPrimeCount: 19,
            specialPrimeCount: 3,
            decompositionBlockCount: 7,
            keyCount: 3,
        },
    ],
    correlations: [
        {
            identifier: exactSampleCorrelationIdentifiers[0],
            statement:
                'One seed-derived uniform A polynomial is shared by ten public-key shares and their deterministic aggregate.',
        },
        {
            identifier: exactSampleCorrelationIdentifiers[1],
            statement:
                'Each of eight relinearization decomposition blocks has one seed-derived uniform polynomial shared across the roster and deterministic aggregates.',
        },
        {
            identifier: exactSampleCorrelationIdentifiers[2],
            statement:
                'Each runtime relinearization A component is exactly the corresponding round-one right aggregate and contributes eight duplicate component views, not fresh samples.',
        },
        {
            identifier: exactSampleCorrelationIdentifiers[3],
            statement:
                'Round one and round two jointly expose the same secret contribution, its square relation, and the same per-participant ephemeral secret.',
        },
        {
            identifier: exactSampleCorrelationIdentifiers[4],
            statement:
                'Each of six Galois keys and each active decomposition block has one seed-derived uniform polynomial shared across the roster.',
        },
        {
            identifier: exactSampleCorrelationIdentifiers[5],
            statement:
                'Every Galois source relation uses the selected automorphism of the same anchor-bound secret contribution.',
        },
        {
            identifier: exactSampleCorrelationIdentifiers[6],
            statement:
                'The sixty-one deterministic aggregate relations remain public views but are never counted as independent fresh RLWE samples.',
        },
    ],
    distributions: {
        honestSecretContribution: 'centered ternary',
        honestErrors: 'centered binomial with parameter two',
        corruptionCases: [0, 1, 2, 3].map((corruptionCount) => {
            const honestParticipantCount = 10 - corruptionCount;
            return {
                corruptionCount,
                honestParticipantCount,
                honestSecretSupportBeforeKnownShift: [
                    -honestParticipantCount,
                    honestParticipantCount,
                ],
                honestErrorSupport: [
                    -2 * honestParticipantCount,
                    2 * honestParticipantCount,
                ],
                maliciousContributionTreatment:
                    'proof-bounded adversarially known coordinated shift',
            };
        }),
        setupDistributionPurposes: [
            ['secretContribution', 1],
            ['publicKeyError', 2],
            ['relinearizationEphemeralSecret', 3],
            ['relinearizationRoundOneLeftError', 4],
            ['relinearizationRoundOneRightError', 5],
            ['relinearizationRoundTwoError', 6],
            ['galoisKeyError', 7],
            ['anchorHidingSecret', 11],
            ['anchorHidingError', 12],
        ].map(([purpose, canonicalCode]) => ({ purpose, canonicalCode })),
    },
});

const buildJointSetupSampleHybridReduction = (): JsonValue => ({
    status: 'resolved',
    assumptionLeaf: 'jointStructuredRlweCircularKdm',
    advantageExpression: 'Adv_joint_structured_rlwe_circular_kdm',
    replacementOrder: [
        'collectivePublicKey',
        'relinearization',
        'galoisLevelFourteen',
        'galoisLevelEighteen',
    ],
    replacementGroups: [
        {
            identifier: 'collectivePublicKey',
            catalogLevel: 22,
            sourceRelationCount: 10,
            deterministicAggregateRelationCount: 1,
            commonUniformPolynomialCount: 1,
            witnessMessages: ['secretContribution', 'publicKeyError'],
        },
        {
            identifier: 'relinearization',
            catalogLevel: 22,
            sourceRelationCount: 240,
            deterministicAggregateRelationCount: 24,
            commonUniformPolynomialCount: 8,
            witnessMessages: [
                'secretContribution',
                'secretContributionSquare',
                'relinearizationEphemeralSecret',
                'relinearizationRoundOneLeftError',
                'relinearizationRoundOneRightError',
                'relinearizationRoundTwoError',
            ],
        },
        {
            identifier: 'galoisLevelFourteen',
            catalogLevel: 14,
            sourceRelationCount: 150,
            deterministicAggregateRelationCount: 15,
            commonUniformPolynomialCount: 15,
            witnessMessages: [
                'secretContribution',
                'automorphicSecretContribution',
                'galoisKeyError',
            ],
        },
        {
            identifier: 'galoisLevelEighteen',
            catalogLevel: 18,
            sourceRelationCount: 210,
            deterministicAggregateRelationCount: 21,
            commonUniformPolynomialCount: 21,
            witnessMessages: [
                'secretContribution',
                'automorphicSecretContribution',
                'galoisKeyError',
            ],
        },
    ],
    exactTotals: {
        sourceRelationCount: 610,
        deterministicAggregateRelationCount: 61,
        completePublicRelationCount: 671,
        commonUniformPolynomialCount: 45,
        distinctPublicPolynomialCount: 716,
        duplicateComponentViewCount: 8,
    },
    correlationRule:
        'One transition replaces the complete joint distribution, preserving all shared-secret, transformed-secret, common-uniform, deterministic-aggregate, VSS, commitment, and proof-auxiliary correlations.',
    corruptionRule:
        'The reduction is instantiated independently for every one of the one hundred seventy-six static corruption subsets with each corrupt contribution retained as its proof-bounded known shift.',
    auxiliaryInputJoinIdentifiers: exactWitnessJoinIdentifiers,
    prohibitedFactorizations: [
        'independent marginal RLWE samples',
        'independent relinearization rounds',
        'independent Galois keys',
        'proof or commitment views omitted from auxiliary input',
    ],
});

const buildSelectedSetupCorrectnessImport = (): JsonValue => ({
    status: 'resolved',
    productionAuthorityField: 'setupCorrectness',
    symbolicResult: 'P_setup_honest_abort_and_correctness',
    checkedOwners: [
        'production setup sampling',
        'production setup population and aggregation',
        'production relinearization and Galois construction',
        'production hybrid key switching',
        'production evaluator noise recurrence',
    ],
    checkedStatements: [
        'collective secret and error bounds include all ten participant contributions',
        'every selected data-prime collective-public-key centered margin is positive',
        'the special basis is coprime to the plaintext modulus for exact plaintext-preserving correction',
        'all selected accepted ballot counts and top-count target variants retain positive evaluator margins',
        'sampler exhaustion is a typed honest abort under the selected bounded candidate-draw catalogs',
        'missing, malformed, noncanonical, inconsistent, or partial setup material cannot mint a terminal capability',
    ],
    excludedClaims: [
        'fairness after adversarial abort',
        'availability after a missing reveal',
        'automatic retry under consumed setup material',
    ],
});

const buildConstructionEvidenceImports = (): JsonValue => [
    {
        identifier: exactConstructionEvidenceImportIdentifiers[0],
        ownerSourcePaths: [],
        requiredClosurePredicate: 'completeConstructionExtractorCorrespondence',
        observedStatus: 'unresolved',
        missingEvidence:
            'The test-only compact semantic owner executes the selected factor-one chronology and derives its relaxed round-by-round error theorem, but no decoded-proof-to-semantic statement, prefix, or matrix adapter and no accepted suite-bound release proof with production theorem correspondence exist. One unselected guarded native public-key candidate exists, but it cannot satisfy this import. Appendix A.1 remains test-only and unavailable without the fixed-tape shared-QRO premise.',
    },
    {
        identifier: exactConstructionEvidenceImportIdentifiers[1],
        ownerSourcePaths: [],
        requiredClosurePredicate:
            'singleFixed512BitQroRestrictionCorrespondenceAndProductionRows',
        observedStatus: 'unresolved',
        missingEvidence:
            'One unselected guarded native compact proof instantiates the current verifier oracle graph, but no selected release-WebAssembly proof and no complete theorem-to-transcript correspondence establish the shared-QRO transform. Fixed SHAKE256 remains an explicit domain-separated ideal-QRO assumption.',
    },
    {
        identifier: exactConstructionEvidenceImportIdentifiers[2],
        ownerSourcePaths: [],
        requiredClosurePredicate:
            'conservativePerPhysicalProofTransformAndExplicitCeremonyUnion',
        observedStatus: 'unresolved',
        missingEvidence:
            'The test-only compact emitted-byte and Appendix A.1 owners derive qPi, qy, qV, tuple, and Merkle coordinates conditionally from one verified transport. One unselected guarded native candidate supplies decoded proof coordinates, but no selected proof bytes exist; the fixed-tape shared-QRO premise is unmintable, and setup-family or ceremony composition is absent.',
    },
    {
        identifier: exactConstructionEvidenceImportIdentifiers[3],
        ownerSourcePaths: [],
        requiredClosurePredicate: 'completeConstructionMaskingCorrespondence',
        observedStatus: 'unresolved',
        missingEvidence:
            'Release generation derives and checks the coefficient-to-view maps, constructs the canonical-input public-covector authority, and gates the production-derived single-proof KMAC census and symbolic quantum-PRF hops before post-lookup mask draws. Live role-18 prefix consumption, sequential conditional-image enforcement, finite-Merkle proof emission, and the joint fixed-KMAC256/fixed-SHAKE256 privacy reduction remain absent; the terminal adaptive simulator remains test-only evidence.',
    },
];

const buildProtocolSchedule = (): JsonValue => ({
    orderedPhases: [
        'reserveActionAndRandomness',
        'publishSignedSetupIntent',
        'publishAllRandomnessCommitments',
        'publishAllRandomnessReveals',
        'derivePublicSetupSeed',
        'deriveMatricesAndCommonPolynomials',
        'distributeAuthenticatedVssMailboxes',
        'verifyVssAndSameSecretRelations',
        'verifyThresholdShareAggregates',
        'verifyPublicKeySharesAndAggregate',
        'publishAndVerifyAllRelinearizationRoundOneSources',
        'freezeAndVerifyRelinearizationRoundOneAggregate',
        'publishAndVerifyGaloisBatches',
        'publishAndVerifyRelinearizationRoundTwoSources',
        'verifyEvaluatorAggregate',
        'reserveTerminalStateAndPublishExactPackage',
    ],
    challengeRule:
        'Every Fiat-Shamir challenge follows the exact statement and complete ordered commitment prefix fixed by the production construction plan.',
    abortCases: exactAbortCaseIdentifiers.map((identifier) => ({
        identifier,
        terminalEffect:
            'typed abort with no accepted setup capability and no partial terminal package',
    })),
    retryRule:
        'There is no fresh retry inside an action. A new attempt requires a newly externally authorized action context and fresh reserved randomness.',
    resumeRule:
        'Resume accepts only authenticated state from the same attempt and reproduces the identical canonical prefix and final bytes.',
    resumeBindings: exactResumeBindingIdentifiers,
    excludedClaims: [
        'adaptive corruption security',
        'perfect erasure',
        'selective-abort independence across separately authorized actions',
    ],
});

const buildHybridGames = (): JsonValue => [
    {
        identifier: exactHybridGameIdentifiers[0],
        status: 'defined',
        transitionReduction: 'identity',
        transitionAdvantage: 'zero',
        change: 'The production execution with static corruptions, adversarial scheduling and rushing, malformed messages, and either exact acceptance or typed abort.',
    },
    {
        identifier: exactHybridGameIdentifiers[1],
        status: 'resolved',
        transitionReduction: 'authenticatedTranscriptReduction',
        transitionAdvantage:
            'Adv_signature_unforgeability + Adv_canonical_hash_binding',
        change: 'Reject every public object that is not an authentic canonical carrier for the fixed roster, ceremony, action, predecessor, and object type.',
    },
    {
        identifier: exactHybridGameIdentifiers[2],
        status: 'resolved',
        transitionReduction: 'commitRevealScheduleReduction',
        transitionAdvantage:
            'Adv_shake_qro_and_collision + Adv_canonical_hash_binding',
        change: 'Condition on a complete binding commitment vector before any reveal and derive matrices and common public polynomials only after all accepted reveals.',
    },
    {
        identifier: exactHybridGameIdentifiers[3],
        status: 'unresolved',
        transitionReduction: 'commonConstructionKnowledgeSoundness',
        transitionAdvantage: 'unresolved_common_construction_knowledge_error',
        change: 'Extract one complete consistent witness tuple for every accepted corrupt setup proof and enforce every cross-family join. The compact construction does not yet supply this extractor.',
    },
    {
        identifier: exactHybridGameIdentifiers[4],
        status: 'resolved',
        transitionReduction: 'jointSetupSampleHybrid',
        transitionAdvantage: 'Adv_joint_structured_rlwe_circular_kdm',
        change: 'Replace honest public-key, relinearization, and Galois samples in their exact correlated groups under the named joint structured assumption.',
    },
    {
        identifier: exactHybridGameIdentifiers[5],
        status: 'unresolved',
        transitionReduction: 'setupFamilySimulationComposition',
        transitionAdvantage: 'unresolved_setup_family_simulation_error',
        change: 'Simulate every honest common proof while preserving the shared transcript, witness joins, abort location, checkpoint behavior, and exact canonical framing.',
    },
    {
        identifier: exactHybridGameIdentifiers[6],
        status: 'resolved',
        transitionReduction: 'mailboxPrivacyReduction',
        transitionAdvantage:
            'Adv_mailbox_authenticated_encryption + Adv_canonical_hash_binding',
        change: 'Replace honest-recipient mailbox plaintexts while retaining only corrupt-recipient plaintexts and public envelope metadata.',
    },
    {
        identifier: exactHybridGameIdentifiers[7],
        status: 'unresolved',
        transitionReduction: 'collectiveSetupHybridComposition',
        transitionAdvantage: 'unresolved_collective_setup_composition_error',
        change: 'Return only the exact accepted public package and owner-local verified outputs or the public secure-abort location.',
    },
];

const buildReductionDag = (): JsonValue => [
    {
        identifier: assumptionNodeIdentifiers[0],
        kind: 'assumption',
        status: 'assumed',
        dependencies: [],
        advantageExpression: 'Adv_joint_structured_rlwe_circular_kdm',
        statement:
            'The exact joint structured RLWE and circular or KDM sample distribution, bases, counts, and correlations in this record is an explicit computational assumption.',
    },
    {
        identifier: assumptionNodeIdentifiers[1],
        kind: 'assumption',
        status: 'assumed',
        dependencies: [],
        advantageExpression: 'Adv_shake_qro_and_collision',
        statement:
            'All domain-separated SHAKE calls are modeled through one quantum oracle under the concrete computational hash assumptions stated by the proof specification.',
    },
    {
        identifier: assumptionNodeIdentifiers[2],
        kind: 'assumption',
        status: 'assumed',
        dependencies: [],
        advantageExpression: 'Adv_canonical_hash_binding',
        statement:
            'Canonical tuple and Merkle bindings fail only through the named hash binding or collapsing assumptions.',
    },
    {
        identifier: assumptionNodeIdentifiers[3],
        kind: 'assumption',
        status: 'assumed',
        dependencies: [],
        advantageExpression: 'Adv_signature_unforgeability',
        statement:
            'Authenticated public carriers rely on the selected signature unforgeability assumption.',
    },
    {
        identifier: assumptionNodeIdentifiers[4],
        kind: 'assumption',
        status: 'assumed',
        dependencies: [],
        advantageExpression: 'Adv_mailbox_authenticated_encryption',
        statement:
            'Private mailbox confidentiality and integrity rely on the selected KEM, key derivation, authenticated encryption, and key-confirmation assumptions.',
    },
    {
        identifier: assumptionNodeIdentifiers[5],
        kind: 'assumption',
        status: 'assumed',
        dependencies: [],
        advantageExpression: 'Adv_external_authorization_or_selective_abort',
        statement:
            'The environment does not authorize unbounded selective retries of one semantic action under fresh action identifiers.',
    },
    {
        identifier: 'productionSampleExposureMapping',
        kind: 'reduction',
        status: 'resolved',
        dependencies: [],
        advantageExpression: 'zero',
        statement:
            'The exact public sample census, bases, deterministic views, and correlations are derived from the production evaluator and setup catalogs.',
    },
    {
        identifier: 'productionWitnessJoinMapping',
        kind: 'reduction',
        status: 'resolved',
        dependencies: [],
        advantageExpression: 'zero',
        statement:
            'The production statement roots and family inventory identify every required corrupt-trustee witness join.',
    },
    {
        identifier: 'commitRevealScheduleReduction',
        kind: 'reduction',
        status: 'resolved',
        dependencies: ['shakeQuantumOracle', 'canonicalHashBinding'],
        advantageExpression:
            'Adv_shake_qro_and_collision + Adv_canonical_hash_binding',
        statement:
            'The public seed is unavailable until the complete ordered commitment vector is fixed and every accepted reveal verifies.',
    },
    {
        identifier: 'authenticatedTranscriptReduction',
        kind: 'reduction',
        status: 'resolved',
        dependencies: ['signatureUnforgeability', 'canonicalHashBinding'],
        advantageExpression:
            'Adv_signature_unforgeability + Adv_canonical_hash_binding',
        statement:
            'Accepted public objects reduce to signed canonical carriers under the fixed roster and action context.',
    },
    {
        identifier: 'mailboxPrivacyReduction',
        kind: 'reduction',
        status: 'resolved',
        dependencies: [
            'mailboxAuthenticatedEncryption',
            'canonicalHashBinding',
        ],
        advantageExpression:
            'Adv_mailbox_authenticated_encryption + Adv_canonical_hash_binding',
        statement:
            'Honest-recipient mailbox plaintext is hidden and every accepted envelope is bound to its source, recipient, action, attempt, and predecessor.',
    },
    {
        identifier: 'abortAndResumeStateMapping',
        kind: 'reduction',
        status: 'resolved',
        dependencies: ['canonicalHashBinding'],
        advantageExpression: 'Adv_canonical_hash_binding',
        statement:
            'Every enumerated abort is terminal for that attempt, while authenticated resume preserves the exact attempt randomness, prefix, and output bytes.',
    },
    {
        identifier: 'jointSetupSampleHybrid',
        kind: 'reduction',
        status: 'resolved',
        dependencies: [
            'jointStructuredRlweCircularKdm',
            'productionSampleExposureMapping',
            'productionWitnessJoinMapping',
        ],
        advantageExpression: 'Adv_joint_structured_rlwe_circular_kdm',
        statement:
            'The exact public-key, relinearization, and Galois groups are replaced jointly, without splitting shared secrets, transformed secrets, deterministic aggregates, common-uniform polynomials, VSS views, commitment views, or proof auxiliary inputs, by the sole named joint structured assumption.',
    },
    {
        identifier: 'commonConstructionKnowledgeSoundness',
        kind: 'reduction',
        status: 'unresolved',
        dependencies: ['canonicalHashBinding'],
        advantageExpression: 'unresolved_common_construction_knowledge_error',
        statement:
            'The test-only compact semantic owner executes the selected chronology and derives its relaxed round-by-round error theorem. A decoded-proof-to-semantic statement, prefix, and matrix adapter, one production compact proof, the fixed-tape shared-QRO premise, and noninteractive composition remain absent.',
    },
    {
        identifier: 'commonConstructionQromTransform',
        kind: 'reduction',
        status: 'unresolved',
        dependencies: ['shakeQuantumOracle'],
        advantageExpression:
            'unresolved_common_construction_qrom_transform_error',
        statement:
            'One unselected guarded native compact proof instantiates the current verifier oracle graph, but no selected release-WebAssembly proof and no complete theorem-to-transcript correspondence establish its extraction terms. Fixed SHAKE256 remains an explicit domain-separated ideal-QRO assumption.',
    },
    {
        identifier: 'commonProofQromComposition',
        kind: 'reduction',
        status: 'unresolved',
        dependencies: ['commonConstructionQromTransform'],
        advantageExpression: 'unresolved_common_proof_qrom_composition_error',
        statement:
            'The test-only compact emitted-byte and Appendix A.1 owners conditionally instantiate qPi, qy, qV, tuple size, proof length, and Merkle arithmetic from a verified transport. One unselected guarded native candidate supplies decoded proof coordinates, but no selected proof bytes exist; the fixed-tape shared-QRO premise is unmintable, and setup-family and ceremony composition remain absent.',
    },
    {
        identifier: 'commonConstructionMaskingCorrespondence',
        kind: 'reduction',
        status: 'unresolved',
        dependencies: ['shakeQuantumOracle'],
        advantageExpression: 'unresolved_common_construction_privacy_error',
        statement:
            'Release generation derives checked coefficient maps and the canonical-input public-covector authority. The adaptive simulator, conditional-entropy lifecycle, finite-Merkle game, and KMAC census remain test-only, with no live role-18 consumer, production proof emission, or joint KMAC256/SHAKE256 privacy reduction.',
    },
    {
        identifier: 'setupFamilySimulationComposition',
        kind: 'obligation',
        status: 'unresolved',
        dependencies: [
            'productionWitnessJoinMapping',
            'commonConstructionKnowledgeSoundness',
            'commonConstructionMaskingCorrespondence',
        ],
        advantageExpression: 'unresolved_setup_family_simulation_error',
        statement:
            'The ten setup proof families have not yet been composed into one simulator and extractor covering the exact shared witness joins.',
    },
    {
        identifier: 'selectedSetupCorrectnessImport',
        kind: 'reduction',
        status: 'resolved',
        dependencies: [
            'productionSampleExposureMapping',
            'productionWitnessJoinMapping',
        ],
        advantageExpression: 'P_setup_honest_abort_and_correctness',
        statement:
            'The production-derived setup correctness authority checks collective secret and error bounds, every collective-public-key centered margin, the exact hybrid basis correction precondition, all accepted ballot-count evaluator traces, and the selected private and public sampler ceilings.',
    },
    {
        identifier: 'collectiveSetupHybridComposition',
        kind: 'obligation',
        status: 'unresolved',
        dependencies: [
            'commitRevealScheduleReduction',
            'authenticatedTranscriptReduction',
            'mailboxPrivacyReduction',
            'abortAndResumeStateMapping',
            'jointSetupSampleHybrid',
            'commonConstructionKnowledgeSoundness',
            'commonConstructionQromTransform',
            'commonProofQromComposition',
            'commonConstructionMaskingCorrespondence',
            'setupFamilySimulationComposition',
            'selectedSetupCorrectnessImport',
            'externalActionAuthorizationAndSelectiveAbort',
        ],
        advantageExpression: 'unresolved_collective_setup_composition_error',
        statement:
            'The terminal malicious collective-setup theorem remains blocked until every non-assumption dependency is resolved.',
    },
];

const buildResidualLedgers = (): JsonValue => [
    {
        identifier: exactResidualLedgerIdentifiers[0],
        rows: [
            {
                source: 'authenticated public transcript',
                symbolicTerm:
                    'Adv_signature_unforgeability + Adv_canonical_hash_binding',
                status: 'resolved',
            },
            {
                source: 'authenticated mailbox integrity',
                symbolicTerm: 'Adv_mailbox_authenticated_encryption',
                status: 'resolved',
            },
            {
                source: 'joint setup sample replacement',
                symbolicTerm: 'Adv_joint_structured_rlwe_circular_kdm',
                status: 'resolved',
            },
            {
                source: 'common-proof knowledge soundness',
                symbolicTerm: 'unresolved_common_construction_knowledge_error',
                status: 'unresolved',
            },
            {
                source: 'collective setup composition',
                symbolicTerm: 'unresolved_collective_setup_composition_error',
                status: 'unresolved',
            },
        ],
    },
    {
        identifier: exactResidualLedgerIdentifiers[1],
        rows: [
            {
                source: 'single domain-separated quantum oracle',
                symbolicTerm: 'Adv_shake_qro_and_collision',
                status: 'assumed',
            },
            {
                source: 'common-proof multi-round transform',
                symbolicTerm:
                    'unresolved_common_construction_qrom_transform_error',
                status: 'unresolved',
            },
            {
                source: 'common-proof physical-proof composition',
                symbolicTerm: 'unresolved_common_proof_qrom_composition_error',
                status: 'unresolved',
            },
            {
                source: 'collective setup composition',
                symbolicTerm: 'unresolved_collective_setup_composition_error',
                status: 'unresolved',
            },
        ],
        queryBudgetRule:
            'Uses the complete selected adversarial query budget for every physical proof and includes verifier, expansion, and accepting-database queries.',
    },
    {
        identifier: exactResidualLedgerIdentifiers[2],
        rows: [
            {
                source: 'missing or inconsistent commitment and reveal',
                symbolicTerm: 'zero_acceptance_under_typed_abort',
                status: 'resolved',
            },
            {
                source: 'rank or sampler exhaustion',
                symbolicTerm: 'honest_abort_conditioning_probability',
                status: 'resolved',
            },
            {
                source: 'selected setup arithmetic and noise correctness',
                symbolicTerm: 'P_setup_honest_abort_and_correctness',
                status: 'resolved',
            },
            {
                source: 'partial terminal package',
                symbolicTerm: 'zero_capability_under_terminal_refusal',
                status: 'resolved',
            },
        ],
    },
    {
        identifier: exactResidualLedgerIdentifiers[3],
        rows: [
            {
                source: 'joint structured setup samples',
                symbolicTerm: 'Adv_joint_structured_rlwe_circular_kdm',
                status: 'assumed',
            },
            {
                source: 'honest-recipient mailbox plaintext',
                symbolicTerm: 'Adv_mailbox_authenticated_encryption',
                status: 'resolved',
            },
            {
                source: 'common-proof masking',
                symbolicTerm: 'unresolved_common_construction_privacy_error',
                status: 'unresolved',
            },
            {
                source: 'setup-family simulation',
                symbolicTerm: 'unresolved_setup_family_simulation_error',
                status: 'unresolved',
            },
            {
                source: 'selective abort across separately authorized actions',
                symbolicTerm: 'Adv_external_authorization_or_selective_abort',
                status: 'assumed',
            },
        ],
        excludedClaims: ['adaptive corruption security', 'perfect erasure'],
    },
];

const buildCertificateBody = (
    productionAuthority: JsonValue,
    sourceAuthority: readonly JsonValue[],
): Record<string, JsonValue> => ({
    schemaIdentifier:
        'sealed-lattice/selected-collective-setup-security-evidence/v1',
    sourceAuthority,
    productionAuthority,
    proofInventory: setupProofInventory.map(
        ([
            family,
            applicationStatementSchemaIdentifier,
            physicalCount,
            logicalCount,
        ]) => ({
            family,
            applicationStatementSchemaIdentifier,
            physicalProofApplicationCount: physicalCount,
            logicalRelationInstanceCount: logicalCount,
        }),
    ),
    proofInventoryTotals: setupProofInventoryTotals,
    game: buildGame(),
    witnessJoins: buildWitnessJoins(),
    sampleRelations: buildSampleRelations(),
    jointSetupSampleHybridReduction: buildJointSetupSampleHybridReduction(),
    selectedSetupCorrectnessImport: buildSelectedSetupCorrectnessImport(),
    constructionEvidenceImports: buildConstructionEvidenceImports(),
    protocolSchedule: buildProtocolSchedule(),
    hybridGames: buildHybridGames(),
    reductionDag: buildReductionDag(),
    residualLedgers: buildResidualLedgers(),
});

export const buildSelectedCollectiveSetupSecurityEvidence = async (
    productionAuthority: JsonValue,
    rootPath = repositoryRoot,
): Promise<JsonValue> => {
    validateProductionAuthority(productionAuthority);
    const sourceAuthority = await deriveSourceAuthority(rootPath);
    const certificateBody = buildCertificateBody(
        productionAuthority,
        sourceAuthority,
    );
    return {
        ...certificateBody,
        recordSha256: canonicalJsonSha256(certificateBody),
    };
};

const expectedInventory = setupProofInventory.map(
    ([
        family,
        applicationStatementSchemaIdentifier,
        physicalCount,
        logicalCount,
    ]) => ({
        family,
        applicationStatementSchemaIdentifier,
        physicalProofApplicationCount: physicalCount,
        logicalRelationInstanceCount: logicalCount,
    }),
);

const validateProductionAuthority = (productionAuthority: JsonValue): void => {
    const authority = requireRecord(
        productionAuthority,
        'Production authority',
    );
    const profile = requireRecord(authority.profile, 'Production profile');
    const expectedProfile = {
        participantCount: 10,
        activeFaultBound: 3,
        reconstructionThreshold: 4,
        finalityQuorum: 7,
        stateWitnessQuorum: 7,
        optionCount: 10,
        polynomialDegree: 32_768,
        plaintextModulus: 257,
    };
    if (canonicalJsonText(profile) !== canonicalJsonText(expectedProfile)) {
        throw new Error(
            'The production roster or algebra profile is not exact.',
        );
    }

    const corruptionClasses = requireArray(
        authority.corruptionClasses,
        'Production corruption classes',
    );
    if (corruptionClasses.length !== 4) {
        throw new Error(
            'The production corruption-class catalog is incomplete.',
        );
    }
    let corruptionSubsetCount = 0;
    for (const [classOrdinal, value] of corruptionClasses.entries()) {
        const corruptionClass = requireRecord(
            value,
            'Production corruption class',
        );
        const corruptionCount = requireInteger(
            corruptionClass.corruptionCount,
            'Production corruption count',
        );
        if (corruptionCount !== classOrdinal) {
            throw new Error(
                'The production corruption classes are misordered.',
            );
        }
        const expectedSubsets = enumerateCorruptionSubsets(10, corruptionCount);
        if (
            canonicalJsonText(
                requireArray(
                    corruptionClass.corruptionSubsets,
                    'Production corruption subsets',
                ),
            ) !== canonicalJsonText(expectedSubsets)
        ) {
            throw new Error(
                'The production corruption-subset catalog is incomplete or altered.',
            );
        }
        const honestParticipantCount = 10 - corruptionCount;
        const expectedCase = {
            corruptionCount,
            honestParticipantCount,
            honestSecretSupportBeforeKnownShift: [
                -honestParticipantCount,
                honestParticipantCount,
            ],
            honestErrorSupport: [
                -2 * honestParticipantCount,
                2 * honestParticipantCount,
            ],
            corruptionSubsets: expectedSubsets,
        };
        if (
            canonicalJsonText(corruptionClass) !==
            canonicalJsonText(expectedCase)
        ) {
            throw new Error(
                'A production corruption case is stale or altered.',
            );
        }
        corruptionSubsetCount += expectedSubsets.length;
    }
    if (corruptionSubsetCount !== 176) {
        throw new Error(
            'The exact static corruption catalog must contain 176 subsets.',
        );
    }

    const expectedProofInventoryTotals = expectedInventory.reduce(
        (totals, entry) => ({
            physicalProofApplicationCount:
                totals.physicalProofApplicationCount +
                entry.physicalProofApplicationCount,
            logicalRelationInstanceCount:
                totals.logicalRelationInstanceCount +
                entry.logicalRelationInstanceCount,
        }),
        {
            physicalProofApplicationCount: 0,
            logicalRelationInstanceCount: 0,
        },
    );
    if (
        canonicalJsonText(
            requireArray(
                authority.proofInventory,
                'Production proof inventory',
            ),
        ) !== canonicalJsonText(expectedInventory) ||
        canonicalJsonText(
            requireRecord(
                authority.proofInventoryTotals,
                'Production proof inventory totals',
            ),
        ) !== canonicalJsonText(expectedProofInventoryTotals)
    ) {
        throw new Error(
            'The production proof multiplicities are stale or altered.',
        );
    }

    const relationPlanBindings = requireArray(
        authority.relationPlanBindings,
        'Production relation-plan bindings',
    );
    if (relationPlanBindings.length !== setupProofInventory.length) {
        throw new Error('The production relation-plan catalog is incomplete.');
    }
    const planHashes = new Set<string>();
    for (const [bindingOrdinal, value] of relationPlanBindings.entries()) {
        const binding = requireRecord(
            value,
            'Production relation-plan binding',
        );
        const expectedFamily = setupProofInventory[bindingOrdinal];
        if (
            binding.family !== expectedFamily?.[0] ||
            binding.applicationStatementSchemaIdentifier !== expectedFamily[1]
        ) {
            throw new Error(
                'The production relation-plan catalog is misordered.',
            );
        }
        const canonicalPlanByteLength = requireInteger(
            binding.canonicalPlanByteLength,
            'Canonical relation-plan byte length',
        );
        const canonicalPlanHash = requireString(
            binding.canonicalPlanHash,
            'Canonical relation-plan hash',
        );
        if (
            canonicalPlanByteLength <= 0 ||
            !/^[0-9a-f]{128}$/u.test(canonicalPlanHash) ||
            planHashes.has(canonicalPlanHash)
        ) {
            throw new Error(
                'A canonical relation-plan binding is invalid or duplicated.',
            );
        }
        planHashes.add(canonicalPlanHash);
        const variants = requireArray(
            binding.variants,
            'Relation-plan variants',
        );
        const expectedVariantCount =
            binding.family === 'evaluatorKeyAggregate'
                ? expectedProfile.optionCount
                : 1;
        if (variants.length !== expectedVariantCount) {
            throw new Error(
                'A production relation-plan variant catalog is incomplete.',
            );
        }
        const selectors = new Set<string>();
        const variantHashes = new Set<string>();
        for (const variantValue of variants) {
            const variant = requireRecord(
                variantValue,
                'Relation-plan variant binding',
            );
            const selector = canonicalJsonText({
                schedulePosition: variant.schedulePosition,
                topCount: variant.topCount,
            });
            const variantHash = requireString(
                variant.canonicalVariantHash,
                'Canonical relation-plan variant hash',
            );
            if (
                selectors.has(selector) ||
                variantHashes.has(variantHash) ||
                !/^[0-9a-f]{128}$/u.test(variantHash)
            ) {
                throw new Error(
                    'A canonical relation-plan variant is invalid or duplicated.',
                );
            }
            selectors.add(selector);
            variantHashes.add(variantHash);
        }
        if (
            binding.family === 'evaluatorKeyAggregate' &&
            variants.some(
                (variantValue, variantOrdinal) =>
                    requireRecord(variantValue, 'Evaluator variant')
                        .topCount !==
                    variantOrdinal + 1,
            )
        ) {
            throw new Error(
                'The evaluator relation-plan variants do not cover every top count.',
            );
        }
    }

    const evaluatorTopology = requireRecord(
        authority.evaluatorTopology,
        'Production evaluator topology',
    );
    const relinearizationEntries = requireArray(
        evaluatorTopology.orderedRelinearizationEntries,
        'Relinearization entries',
    );
    const galoisEntries = requireArray(
        evaluatorTopology.orderedGaloisEntries,
        'Galois entries',
    );
    const completeActionEntries = requireArray(
        evaluatorTopology.completeActionEntries,
        'Complete evaluator entries',
    );
    if (
        relinearizationEntries.length !== 1 ||
        galoisEntries.length !== 6 ||
        completeActionEntries.length !== 7 ||
        requireArray(evaluatorTopology.orderedDataPrimes, 'Data primes')
            .length !== 23 ||
        requireArray(evaluatorTopology.orderedSpecialPrimes, 'Special primes')
            .length !== 3
    ) {
        throw new Error('The production evaluator topology is not exact.');
    }
    const expectedGaloisEntries = [
        [15, 14, 5],
        [19, 14, 5],
        [219, 14, 5],
        [257, 18, 7],
        [1_025, 18, 7],
        [8_193, 18, 7],
    ];
    if (
        galoisEntries.some((entryValue, index) => {
            const entry = requireRecord(entryValue, 'Galois entry');
            const expected = expectedGaloisEntries[index];
            return (
                entry.kind !== 'galois' ||
                entry.schedulePosition !== index ||
                entry.galoisElement !== expected?.[0] ||
                entry.catalogLevel !== expected[1] ||
                entry.dataPrimeCount !== expected[1] + 1 ||
                entry.specialPrimeCount !== 3 ||
                entry.decompositionBlockCount !== expected[2]
            );
        })
    ) {
        throw new Error(
            'The production Galois topology is stale or reordered.',
        );
    }

    const sampleCensus = requireRecord(
        authority.sampleCensus,
        'Production sample census',
    );
    const sampleSummary = requireRecord(
        sampleCensus.summary,
        'Production sample summary',
    );
    const expectedSampleSummary = {
        sourceRelationCountPerParticipant: 61,
        sourceRelationCountForRoster: 610,
        deterministicDerivedRelationCount: 61,
        completePublicRelationCount: 671,
        finalRuntimeKeyRelationCount: 45,
        commonUniformPolynomialCount: 45,
        generatedComponentViewCount: 724,
        distinctPublicPolynomialCount: 716,
        duplicateComponentViewCount: 8,
    };
    if (
        canonicalJsonText(sampleSummary) !==
        canonicalJsonText(expectedSampleSummary)
    ) {
        throw new Error(
            'The production public-sample census is stale or altered.',
        );
    }
    const sampleRows = requireArray(
        sampleCensus.rows,
        'Production sample rows',
    );
    if (sampleRows.length !== 4) {
        throw new Error(
            'The production public-sample row catalog is incomplete.',
        );
    }

    const witnessTopology = requireRecord(
        authority.witnessCommitmentTopology,
        'Production witness commitment topology',
    );
    const sharingCoordinates = requireArray(
        witnessTopology.orderedVssSharingDataPrimeCoordinates,
        'VSS sharing coordinates',
    );
    if (
        sharingCoordinates.length !== 8 ||
        sharingCoordinates.some(
            (coordinateValue, index) =>
                requireRecord(coordinateValue, 'VSS sharing coordinate')
                    .dataPrimeIndex !== index,
        ) ||
        canonicalJsonText(
            requireArray(
                witnessTopology.anchorCommitmentDataPrimeIndices,
                'Anchor commitment indices',
            ),
        ) !== canonicalJsonText([0, 1, 2]) ||
        witnessTopology.anchorCommitmentModuleRank !== 1 ||
        witnessTopology.anchorHidingSecretWidth !== 2 ||
        witnessTopology.anchorHidingErrorWidth !== 1
    ) {
        throw new Error('The production witness commitment topology is stale.');
    }

    const setupCorrectness = requireRecord(
        authority.setupCorrectness,
        'Production setup correctness authority',
    );
    const collectivePublicKeyMargins = requireArray(
        setupCorrectness.collectivePublicKeyMinimumCenteredMargins,
        'Collective public-key centered margins',
    );
    const maximumEvaluatorError = requireString(
        setupCorrectness.maximumEvaluatorErrorCoefficientBoundDecimal,
        'Maximum evaluator error bound',
    );
    const minimumEvaluatorMargin = requireString(
        setupCorrectness.minimumEvaluatorDecryptionMarginDecimal,
        'Minimum evaluator decryption margin',
    );
    const specialBasisProduct = requireString(
        setupCorrectness.specialBasisModulusProductDecimal,
        'Special-basis modulus product',
    );
    const participantSecretCoefficientBound = requireInteger(
        setupCorrectness.participantSecretCoefficientBound,
        'Participant secret coefficient bound',
    );
    const participantErrorCoefficientBound = requireInteger(
        setupCorrectness.participantErrorCoefficientBound,
        'Participant error coefficient bound',
    );
    if (
        participantSecretCoefficientBound !== 1 ||
        participantErrorCoefficientBound !== 2 ||
        setupCorrectness.collectiveSecretCoefficientBound !==
            expectedProfile.participantCount *
                participantSecretCoefficientBound ||
        setupCorrectness.collectiveErrorCoefficientBound !==
            expectedProfile.participantCount *
                participantErrorCoefficientBound ||
        setupCorrectness.collectivePublicKeyScaledErrorCoefficientBound !==
            5_140 ||
        collectivePublicKeyMargins.length !== 23 ||
        collectivePublicKeyMargins.some(
            (margin) =>
                typeof margin !== 'number' ||
                !Number.isSafeInteger(margin) ||
                margin <= 0,
        ) ||
        setupCorrectness.keySwitchDataPrimesPerBlock !== 3 ||
        setupCorrectness.specialBasisIsCoprimeToPlaintextModulus !== true ||
        setupCorrectness.acceptedBallotCountCases !==
            expectedProfile.participantCount ||
        setupCorrectness.evaluatorTargetTraceCount !==
            expectedProfile.participantCount * expectedProfile.optionCount ||
        setupCorrectness.maximumPrivateSamplerCandidateDrawsPerOutput !== 64 ||
        setupCorrectness.maximumPublicSamplerCandidateDrawsPerOutput !== 128 ||
        !/^[1-9][0-9]*$/u.test(specialBasisProduct) ||
        !/^[1-9][0-9]*$/u.test(maximumEvaluatorError) ||
        !/^[1-9][0-9]*$/u.test(minimumEvaluatorMargin)
    ) {
        throw new Error(
            'The production setup correctness authority is stale or incomplete.',
        );
    }
};

const validateIdentifierCatalog = (
    values: JsonValue[],
    expectedIdentifiers: readonly string[],
    description: string,
): void => {
    const identifiers = values.map((value) =>
        requireString(
            requireRecord(value, description).identifier,
            description,
        ),
    );
    if (
        canonicalJsonText(identifiers) !==
        canonicalJsonText(expectedIdentifiers)
    ) {
        throw new Error(
            `${description} is incomplete, duplicated, or reordered.`,
        );
    }
};

const validateReductionDag = (dagValue: JsonValue): readonly string[] => {
    const nodes = requireArray(dagValue, 'Reduction DAG');
    validateIdentifierCatalog(
        nodes,
        requiredReductionNodeIdentifiers,
        'Reduction DAG node catalog',
    );
    const nodesByIdentifier = new Map<string, Record<string, JsonValue>>();
    const nodeOrdinalByIdentifier = new Map<string, number>();
    for (const [nodeOrdinal, nodeValue] of nodes.entries()) {
        const node = requireRecord(nodeValue, 'Reduction DAG node');
        const identifier = requireString(
            node.identifier,
            'Reduction DAG node identifier',
        );
        if (nodesByIdentifier.has(identifier)) {
            throw new Error('The reduction DAG contains a duplicate node.');
        }
        nodesByIdentifier.set(identifier, node);
        nodeOrdinalByIdentifier.set(identifier, nodeOrdinal);
    }
    for (const [nodeOrdinal, nodeValue] of nodes.entries()) {
        const node = requireRecord(nodeValue, 'Reduction DAG node');
        const identifier = requireString(
            node.identifier,
            'Reduction DAG node identifier',
        );
        const kind = requireString(node.kind, 'Reduction DAG node kind');
        const status = requireString(node.status, 'Reduction DAG node status');
        if (!['assumption', 'reduction', 'obligation'].includes(kind)) {
            throw new Error('The reduction DAG contains an unknown node kind.');
        }
        if (!['assumed', 'resolved', 'unresolved'].includes(status)) {
            throw new Error(
                'The reduction DAG contains an unknown node status.',
            );
        }
        if ((kind === 'assumption') !== (status === 'assumed')) {
            throw new Error(
                'Only explicit assumption leaves may use assumed status.',
            );
        }
        const advantageExpression = requireString(
            node.advantageExpression,
            'Reduction advantage expression',
        );
        if (
            /\d/u.test(advantageExpression) ||
            /bits?/iu.test(advantageExpression)
        ) {
            throw new Error(
                'Numeric estimator bit costs may not be used as reduction advantages.',
            );
        }
        const dependencies = requireArray(
            node.dependencies,
            'Reduction DAG dependencies',
        ).map((dependency) =>
            requireString(dependency, 'Reduction DAG dependency'),
        );
        if (new Set(dependencies).size !== dependencies.length) {
            throw new Error('A reduction DAG node repeats a dependency.');
        }
        for (const dependency of dependencies) {
            const dependencyOrdinal = nodeOrdinalByIdentifier.get(dependency);
            if (
                dependencyOrdinal === undefined ||
                dependencyOrdinal >= nodeOrdinal ||
                dependency === identifier
            ) {
                throw new Error(
                    'The reduction DAG has a missing, self-referential, reordered, or cyclic dependency.',
                );
            }
            const dependencyStatus = requireString(
                nodesByIdentifier.get(dependency)?.status,
                'Reduction dependency status',
            );
            if (status === 'resolved' && dependencyStatus === 'unresolved') {
                throw new Error(
                    'A resolved reduction may not depend on an unresolved obligation.',
                );
            }
        }
    }
    const unresolved = nodes
        .map((nodeValue) => requireRecord(nodeValue, 'Reduction DAG node'))
        .filter(
            (node) =>
                node.kind !== 'assumption' && node.status === 'unresolved',
        )
        .map((node) =>
            requireString(node.identifier, 'Unresolved reduction identifier'),
        );
    if (
        canonicalJsonText(unresolved) !==
        canonicalJsonText(unresolvedNodeIdentifiers)
    ) {
        throw new Error(
            'The unresolved non-assumption reduction catalog is stale or incomplete.',
        );
    }
    return unresolved;
};

type CollectiveSetupSecurityValidationSummary = {
    readonly assumptionLeafCount: number;
    readonly corruptionSubsetCount: number;
    readonly logicalRelationInstanceCount: number;
    readonly physicalProofApplicationCount: number;
    readonly readyForClosure: boolean;
    readonly unresolvedNonAssumptionLeaves: readonly string[];
};

export const validateSelectedCollectiveSetupSecurityEvidence = (
    evidence: JsonValue,
    expectedEvidence: JsonValue,
): CollectiveSetupSecurityValidationSummary => {
    const record = requireRecord(
        evidence,
        'Collective-setup security evidence',
    );
    const expectedRecord = requireRecord(
        expectedEvidence,
        'Expected collective-setup security evidence',
    );
    const recordedDigest = requireString(
        record.recordSha256,
        'Collective-setup evidence digest',
    );
    const body = { ...record };
    delete body.recordSha256;
    if (recordedDigest !== canonicalJsonSha256(body)) {
        throw new Error('The collective-setup evidence digest does not match.');
    }
    const sourceAuthority = requireArray(
        record.sourceAuthority,
        'Collective-setup source authority',
    );
    const expectedSourceAuthority = requireArray(
        expectedRecord.sourceAuthority,
        'Expected collective-setup source authority',
    );
    if (
        canonicalJsonText(sourceAuthority) !==
        canonicalJsonText(expectedSourceAuthority)
    ) {
        throw new Error('The collective-setup source authority is stale.');
    }
    validateProductionAuthority(record.productionAuthority ?? null);
    if (
        canonicalJsonText(record.productionAuthority ?? null) !==
        canonicalJsonText(expectedRecord.productionAuthority ?? null)
    ) {
        throw new Error('The production-derived authority snapshot is stale.');
    }

    const proofInventory = requireArray(
        record.proofInventory,
        'Security proof inventory',
    );
    if (
        canonicalJsonText(proofInventory) !==
        canonicalJsonText(expectedInventory)
    ) {
        throw new Error(
            'The security proof multiplicities are stale or altered.',
        );
    }
    if (
        canonicalJsonText(record.proofInventoryTotals ?? null) !==
        canonicalJsonText(setupProofInventoryTotals)
    ) {
        throw new Error('The security proof inventory totals are stale.');
    }

    const game = requireRecord(record.game, 'Collective-setup game');
    const corruptionModel = requireRecord(
        game.corruptionModel,
        'Collective-setup corruption model',
    );
    if (
        corruptionModel.maximumCorruptionCount !== 3 ||
        corruptionModel.exactSubsetCount !== 176 ||
        canonicalJsonText(
            corruptionModel.exactSubsetsByCorruptionCount ?? null,
        ) !==
            canonicalJsonText(
                [0, 1, 2, 3].map((corruptionCount) => ({
                    corruptionCount,
                    subsets: enumerateCorruptionSubsets(10, corruptionCount),
                })),
            )
    ) {
        throw new Error('The game omits or alters a static corruption case.');
    }

    validateIdentifierCatalog(
        requireArray(record.witnessJoins, 'Witness joins'),
        exactWitnessJoinIdentifiers,
        'Witness-join catalog',
    );
    const sampleRelations = requireRecord(
        record.sampleRelations,
        'Sample relations',
    );
    validateIdentifierCatalog(
        requireArray(sampleRelations.correlations, 'Sample correlations'),
        exactSampleCorrelationIdentifiers,
        'Sample-correlation catalog',
    );
    if (
        canonicalJsonText(record.jointSetupSampleHybridReduction ?? null) !==
        canonicalJsonText(buildJointSetupSampleHybridReduction())
    ) {
        throw new Error(
            'The exact joint setup-sample hybrid reduction is stale or incomplete.',
        );
    }
    if (
        canonicalJsonText(record.selectedSetupCorrectnessImport ?? null) !==
        canonicalJsonText(buildSelectedSetupCorrectnessImport())
    ) {
        throw new Error(
            'The selected setup correctness import is stale or incomplete.',
        );
    }
    const constructionEvidenceImports = requireArray(
        record.constructionEvidenceImports,
        'Construction evidence imports',
    );
    validateIdentifierCatalog(
        constructionEvidenceImports,
        exactConstructionEvidenceImportIdentifiers,
        'Construction evidence import catalog',
    );
    if (
        canonicalJsonText(constructionEvidenceImports) !==
        canonicalJsonText(buildConstructionEvidenceImports())
    ) {
        throw new Error(
            'A common-construction evidence import is stale or overstated.',
        );
    }
    const protocolSchedule = requireRecord(
        record.protocolSchedule,
        'Protocol schedule',
    );
    validateIdentifierCatalog(
        requireArray(protocolSchedule.abortCases, 'Abort cases'),
        exactAbortCaseIdentifiers,
        'Abort-case catalog',
    );
    if (
        canonicalJsonText(protocolSchedule.resumeBindings ?? null) !==
        canonicalJsonText(exactResumeBindingIdentifiers)
    ) {
        throw new Error(
            'The authenticated-resume binding catalog is incomplete.',
        );
    }

    const hybridGames = requireArray(record.hybridGames, 'Hybrid games');
    validateIdentifierCatalog(
        hybridGames,
        exactHybridGameIdentifiers,
        'Hybrid-game catalog',
    );
    const expectedHybridStatuses = [
        'defined',
        'resolved',
        'resolved',
        'unresolved',
        'resolved',
        'unresolved',
        'resolved',
        'unresolved',
    ] as const;
    for (const [hybridOrdinal, hybridValue] of hybridGames.entries()) {
        const hybrid = requireRecord(hybridValue, 'Hybrid game');
        if (hybrid.status !== expectedHybridStatuses[hybridOrdinal]) {
            throw new Error(
                'A hybrid-game transition status is overstated or stale.',
            );
        }
        const transitionReduction = requireString(
            hybrid.transitionReduction,
            'Hybrid-game transition reduction',
        );
        if (
            transitionReduction !== 'identity' &&
            !requiredReductionNodeIdentifiers.includes(
                transitionReduction as (typeof requiredReductionNodeIdentifiers)[number],
            )
        ) {
            throw new Error(
                'A hybrid-game transition references a missing reduction.',
            );
        }
        const transitionAdvantage = requireString(
            hybrid.transitionAdvantage,
            'Hybrid-game transition advantage',
        );
        if (
            /\d/u.test(transitionAdvantage) ||
            /bits?/iu.test(transitionAdvantage)
        ) {
            throw new Error(
                'Numeric estimator bit costs may not be used as hybrid advantages.',
            );
        }
    }

    const unresolved = validateReductionDag(record.reductionDag ?? null);
    const ledgers = requireArray(record.residualLedgers, 'Residual ledgers');
    validateIdentifierCatalog(
        ledgers,
        exactResidualLedgerIdentifiers,
        'Residual-ledger catalog',
    );
    for (const ledgerValue of ledgers) {
        const ledger = requireRecord(ledgerValue, 'Residual ledger');
        const rows = requireArray(ledger.rows, 'Residual ledger rows');
        if (rows.length === 0) {
            throw new Error('A residual ledger may not be empty.');
        }
        for (const rowValue of rows) {
            const row = requireRecord(rowValue, 'Residual ledger row');
            const symbolicTerm = requireString(
                row.symbolicTerm,
                'Residual-ledger symbolic term',
            );
            if (/\d/u.test(symbolicTerm) || /bits?/iu.test(symbolicTerm)) {
                throw new Error(
                    'Numeric estimator bit costs may not appear in a residual ledger.',
                );
            }
            if (
                row.status !== 'assumed' &&
                row.status !== 'resolved' &&
                row.status !== 'unresolved'
            ) {
                throw new Error('A residual-ledger row has an invalid status.');
            }
        }
    }

    const expectedBody = { ...expectedRecord };
    delete expectedBody.recordSha256;
    if (canonicalJsonText(body) !== canonicalJsonText(expectedBody)) {
        throw new Error(
            'The collective-setup security evidence is stale or altered.',
        );
    }
    return {
        assumptionLeafCount: assumptionNodeIdentifiers.length,
        corruptionSubsetCount: 176,
        logicalRelationInstanceCount:
            setupProofInventoryTotals.logicalRelationInstanceCount,
        physicalProofApplicationCount:
            setupProofInventoryTotals.physicalProofApplicationCount,
        readyForClosure: unresolved.length === 0,
        unresolvedNonAssumptionLeaves: unresolved,
    };
};

export const requireSelectedCollectiveSetupSecurityClosure = (
    evidence: JsonValue,
    expectedEvidence: JsonValue,
): void => {
    const summary = validateSelectedCollectiveSetupSecurityEvidence(
        evidence,
        expectedEvidence,
    );
    if (!summary.readyForClosure) {
        throw new Error(
            `Collective-setup security closure is blocked by: ${summary.unresolvedNonAssumptionLeaves.join(', ')}.`,
        );
    }
};
