import {
    compileCompleteAuthenticationFrameWork,
    compileCompleteCredentialIntentBounds,
    compileCompletedAuthenticationCensus,
    compileCredentialIntentBoundsThroughBallot,
    compileSignatureHashInputs,
    compilePurposeSignatureWork,
} from '#tests/authentication-work-model.js';
import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import { compileFheKeySourceScreenResources } from '#tests/fhe-key-source-resource-model.js';
import { compilePreparationResources } from '#tests/preparation-resource-model.js';
import { compilePublicEvaluationHashCensus } from '#tests/public-evaluation-hash-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSelectedOpeningTransformCensus } from '#tests/selected-opening-transform-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import {
    compileSetupSelectionCensus,
    countStagePath,
    preparationStagePath,
} from '#tests/setup-selection-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { compileSetupShareArithmeticBounds } from '#tests/setup-share-arithmetic-model.js';
import {
    compileFheGadgetArithmeticBounds,
    compileRecipientKeyArithmeticBounds,
    compileSourceArithmeticBounds,
    compileSourceCoefficientAllocation,
} from '#tests/source-coefficient-allocation-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
    largestSupportedProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';

export const renderAuthenticationFramesAndCompletedPrefix = (): string[] => {
    const completion = completionProfile();
    const work = compilePurposeSignatureWork();
    return [
        '## Authentication frames and completed prefix',
        '',
        'Each credential commits twelve purpose keys under one Merkle root. A purpose signs one original frame; identical replay preserves that frame and still incurs actual work. Every message representative binds the root, purpose, complete length and bytes. The fixed-loop signature has no rejection-sampling failure term.',
        '',
        table(
            [
                'Purpose',
                'Message bytes',
                'Bound frame bytes',
                'Representative input bytes',
                'Representative permutations',
            ],
            compileCompleteAuthenticationFrameWork().map((role) => [
                role.purpose,
                formatCount(role.messageBytes),
                formatCount(role.frameBytes),
                formatCount(role.representativeInputBytes),
                formatCount(role.representativePermutations),
            ]),
        ),
        '',
        table(
            ['Hash purpose', 'Input bytes', 'Output bytes', 'Permutations'],
            compileSignatureHashInputs().rows.map((row) => [
                row.purpose,
                formatCount(row.inputBytes),
                formatCount(row.outputBytes),
                formatCount(row.permutations),
            ]),
        ),
        '',
        table(
            ['Construction', 'Bound'],
            [
                [
                    'Complete key-tree hash calls',
                    formatCount(work.keyHashCalls),
                ],
                [
                    'Complete key-tree permutations',
                    formatCount(work.keyPermutations),
                ],
                [
                    'Maximum first-signature hash calls',
                    formatCount(work.maximumSignatureHashCalls),
                ],
                [
                    'Maximum signature-verification hash calls',
                    formatCount(work.maximumVerificationHashCalls),
                ],
                [
                    'Mandatory credential predecessor gates',
                    formatCount(work.credentialPredecessorGates),
                ],
            ],
        ),
        '',
        'The following counts concern original first-evaluated intents. Missing retained state cannot recreate authority, and uncertain acknowledgement preserves the original frame. Public record counts do not bound verification, arbitrary repeated work or the lifetime original-credential population.',
        '',
        table(
            [
                'Credential role',
                'Through-ballot purposes',
                'First intent bound',
            ],
            compileCredentialIntentBoundsThroughBallot().map((row) => [
                row.role,
                row.purposes.join(', '),
                formatCount(row.firstEvaluatedIntentBound),
            ]),
        ),
        '',
        table(
            [
                'Branch',
                'Credential role',
                'Fixed purposes',
                'Optional purposes',
                'First intent bound',
            ],
            compileCompleteCredentialIntentBounds(
                completion.participantCount,
            ).map((row) => [
                row.branch,
                row.role,
                row.fixedPurposes.join(', '),
                row.optionalPurposes.join(', '),
                formatCount(row.firstEvaluatedIntentBound),
            ]),
        ),
        '',
        table(
            [
                'Signed ballots',
                'Signed records',
                'Signature bytes',
                'Application message bytes',
                'Bound frame bytes',
                'Representative permutations',
            ],
            [0, completion.participantCount].map((ballots) => {
                const row = compileCompletedAuthenticationCensus(
                    completion.participantCount,
                    BigInt(completion.participantCount),
                    ballots,
                );
                return [
                    formatCount(ballots),
                    formatCount(row.signatures),
                    formatCount(row.signatureBytes),
                    formatCount(row.signingMessageBytes),
                    formatCount(row.signingFrameBytes),
                    formatCount(row.representativePermutations),
                ];
            }),
        ),
        '',
    ];
};

export const renderRecipientKeyArithmeticBounds = (): string[] => [
    '## Recipient-key arithmetic bounds',
    '',
    'The original recipient key uses the same fixed-limb generator at the share modulus. Its retained-key check reduces a*s+b; the centered public key adds one bounded coefficient term to the sparse product, not another secret-support position. Both rows check normalization, leading-prefix reduction and signed machine ranges. For an authentic generated key the restored residue is its original error, whose negative endpoint is permitted and whose positive endpoint is excluded by the native check. Public-key validation, source-stream comparisons, allocation history and custody remain separate obligations.',
    '',
    table(
        [
            'Operation',
            'Limbs',
            'Maximum quotient estimate',
            'Maximum centered quotient magnitude',
            'Maximum normalization carry magnitude',
        ],
        Object.entries(compileRecipientKeyArithmeticBounds()).map(
            ([operation, row]) => [
                operation === 'generated'
                    ? 'Generation'
                    : 'Retained-key validation',
                formatCount(row.limbs),
                formatCount(row.maximumQuotientEstimate),
                formatCount(row.maximumQuotient),
                formatCount(row.maximumNormalizationCarry),
            ],
        ),
    ),
    '',
];

export const renderOriginalSourceArithmeticBounds = (): string[] => {
    const completion = completionProfile();
    return [
        '## Original-source arithmetic bounds',
        '',
        'These bounds apply to the original first FHE key coordinate with centered common coefficients, the fixed sparse-secret support and the bounded source error. Every supported profile is checked against the transform range, signed machine integers, reducer leading-digit and two-correction premises, and the emitted quotient/carry widths. They rule out the named arithmetic refusals for those source inputs; they are not peak-allocation bounds or claims about other setup equations.',
        '',
        table(
            [
                'Participants / options',
                'Limbs',
                'Leading modulus digit',
                'Maximum quotient estimate',
                'Maximum centered quotient magnitude',
                'Maximum witness carry magnitude',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                largestSupportedProfile(),
            ].map((profile) => {
                const row = compileSourceArithmeticBounds(profile);
                return [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    formatCount(row.limbs),
                    formatCount(row.leadingModulusDigit),
                    formatCount(row.maximumQuotientEstimate),
                    formatCount(row.maximumQuotient),
                    formatCount(row.maximumWitnessCarry),
                ];
            }),
        ),
        '',
    ];
};

export const renderGeneratedSetupArithmeticBounds = (): string[] => {
    const completion = completionProfile();
    return [
        '## Generated setup arithmetic bounds',
        '',
        'The FHE-key bound additionally covers both signs of every gadget power multiplying a ternary source or its signed automorphism. It checks all supported profiles against the same scalar reducer, machine ranges and quotient/carry widths as the original first-coordinate case. The table summarizes all gadget powers in each displayed profile. These are arithmetic refusal bounds, not a complete generation/allocation or proof-simulation result.',
        '',
        table(
            [
                'Participants / options',
                'Gadget powers',
                'Largest direct multiplier bits',
                'Maximum quotient estimate',
                'Maximum centered quotient magnitude',
                'Maximum witness carry magnitude',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                largestSupportedProfile(),
            ].map((profile) => {
                const rows = compileFheGadgetArithmeticBounds(profile);
                const maximum = (values: bigint[]) =>
                    values.reduce(
                        (largest, value) => (value > largest ? value : largest),
                        0n,
                    );
                return [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    formatCount(rows.length),
                    formatCount(
                        maximum(
                            rows.map((row) => row.directMultiplierMagnitude),
                        ).toString(2).length,
                    ),
                    formatCount(
                        maximum(rows.map((row) => row.maximumQuotientEstimate)),
                    ),
                    formatCount(
                        maximum(rows.map((row) => row.maximumQuotient)),
                    ),
                    formatCount(
                        maximum(rows.map((row) => row.maximumWitnessCarry)),
                    ),
                ];
            }),
        ),
        '',
        'Share generation is checked for arbitrary canonical recipient polynomials without assuming a valid key witness. The bounds cover signed sharing evaluations, low/high decomposition and offset, both ciphertext components, normalization, reduction and emitted carry widths. Every supported profile is checked; the table shows the constant component and its linear counterpart separately. A wider unsupported limb control exceeds the signed offset range, so passing the actual profile checks is load-bearing.',
        '',
        table(
            [
                'Participants / options',
                'Component',
                'Limb bits',
                'Offset magnitude bits',
                'Maximum quotient estimate',
                'Maximum witness carry magnitude',
                'Signed carry bits',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                largestSupportedProfile(),
            ].flatMap((profile) =>
                compileSetupShareArithmeticBounds(profile).map((row) => [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    row.component,
                    formatCount(profile.shareLifting.limbBits),
                    formatCount(row.maximumOffset.toString(2).length),
                    formatCount(row.maximumQuotientEstimate),
                    formatCount(row.maximumWitnessCarry),
                    formatCount(row.carryBits),
                ]),
            ),
        ),
        '',
    ];
};

export const renderSourceCoefficientNormalizationComparison = (): string[] => {
    const completion = completionProfile();
    return [
        '## Source coefficient normalization comparison',
        '',
        'For one original FHE source coordinate, this conditional comparison counts the centered residues that make the pinned scalar BigUint constructor shrink its allocation. It uses independent source randomness and a uniform common polynomial: one nonzero sparse coefficient is a unit, so every output coefficient has a uniform marginal. The coordinate union bound needs no independence between coefficients. The table does not bound allocation for fixed adversarial inputs, all registrations, all source families, complete operations or provider failures; the source-stream and common-sampling comparisons retain their separate costs.',
        '',
        table(
            [
                'Participants / options',
                'Modulus bits',
                'Constructor u32 capacity',
                'Shrink below magnitude bits',
                'Coefficients',
                'One-coordinate exception bits',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                largestSupportedProfile(),
            ].map((profile) => {
                const row = compileSourceCoefficientAllocation(profile);
                return [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    formatCount(row.modulusBits),
                    formatCount(row.constructorWords),
                    formatCount(row.shrinkMagnitudeBits),
                    formatCount(row.coefficientCount),
                    formatCount(row.exceptionBits),
                ];
            }),
        ),
        '',
    ];
};

export const renderRecipientKeyCensus = (): string[] => {
    const registrationKey = compileRecipientKeyCensus();
    return [
        '## Recipient key census',
        '',
        'Registration authenticates the complete canonical recipient polynomial. The bounded key equation is checked in the linked release relation; registration carries no separate key proof.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Polynomial degree', formatCount(registrationKey.degree)],
                ['Ciphertext modulus', formatCount(registrationKey.modulus)],
                ['Honest secret support', formatCount(registrationKey.support)],
                [
                    'Honest quotient magnitude bound',
                    formatCount(registrationKey.honestQuotient),
                ],
                [
                    'Honest carry magnitude bound',
                    formatCount(registrationKey.honestCarry),
                ],
                [
                    'Maximum accepted integer limb residual magnitude',
                    formatCount(registrationKey.maximumLimbResidual),
                ],
                [
                    'Canonical public-key bytes',
                    formatCount(registrationKey.publicKeyBytes),
                ],
            ],
        ),
        '',
    ];
};

export const renderRegistrationEnrollmentCensus = (): string[] => {
    const registrationEnrollment = compileRegistrationEnrollmentCensus();
    return [
        '## Registration enrollment census',
        '',
        'The combined enrollment record binds a canonical public username, the actual signing credential, the hash of the recipient public key and the encrypted-source bindings to the poll, whose identity names the runtime. Separate data keys seal the original recipient key, signing seed and per-family source seeds; the encrypted local root retains those keys and references every record. From the roster transition on, the root also references the roster proposal and, once signed, its signature. Payload counts exclude database metadata and browser-managed root-key storage. Enrollment retains its staged arrays through the atomic commit; its allocation allowance counts staged arrays, record-copy arrays and Blob payload snapshots separately and does not bound garbage collection or browser overhead.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Signing public-key bytes',
                    formatCount(registrationEnrollment.signingPublicKeyBytes),
                ],
                [
                    'Signature bytes',
                    formatCount(registrationEnrollment.signatureBytes),
                ],
                [
                    'Maximum canonical username bytes',
                    formatCount(registrationEnrollment.maximumUsernameBytes),
                ],
                [
                    'Maximum poll-definition bytes',
                    formatCount(
                        registrationEnrollment.maximumPollDefinitionBytes,
                    ),
                ],
                [
                    'Poll-definition framing bytes',
                    formatCount(
                        registrationEnrollment.pollDefinitionOverheadBytes,
                    ),
                ],
                [
                    'Maximum organizer input bytes',
                    formatCount(
                        registrationEnrollment.maximumOrganizerInputBytes,
                    ),
                ],
                [
                    'Maximum join input bytes',
                    formatCount(registrationEnrollment.maximumJoinInputBytes),
                ],
                [
                    'Maximum username ingress bytes',
                    formatCount(
                        registrationEnrollment.maximumUsernameIngressBytes,
                    ),
                ],
                [
                    'Maximum encoded header bytes',
                    formatCount(registrationEnrollment.maximumHeaderBytes),
                ],
                [
                    'Maximum header input bytes',
                    formatCount(registrationEnrollment.maximumHeaderInputBytes),
                ],
                [
                    'Recipient-key capsule bytes',
                    formatCount(registrationEnrollment.recipientCapsuleBytes),
                ],
                [
                    'Signing-seed capsule bytes',
                    formatCount(registrationEnrollment.signingCapsuleBytes),
                ],
                [
                    'Maximum published encrypted-source bytes',
                    formatCount(
                        registrationEnrollment.maximumSourceCiphertextBytes,
                    ),
                ],
                [
                    'Maximum retained source seed capsule bytes',
                    formatCount(
                        registrationEnrollment.maximumSourceCapsuleBytes,
                    ),
                ],
                [
                    'Maximum enrollment staged payload bytes',
                    formatCount(
                        registrationEnrollment.maximumEnrollmentStagedPayloadBytes,
                    ),
                ],
                [
                    'Maximum enrollment staged source records',
                    formatCount(
                        registrationEnrollment.maximumEnrollmentStagedSourceRecords,
                    ),
                ],
                [
                    'Enrollment staged arrays, record copies and Blob payload allowance',
                    formatCount(
                        registrationEnrollment.maximumEnrollmentStagingAndBlobPayloadBytes,
                    ),
                ],
                [
                    'Maximum enrollment records before proposal signing',
                    formatCount(
                        registrationEnrollment.maximumEnrollmentRecords,
                    ),
                ],
                [
                    'Maximum retained records',
                    formatCount(registrationEnrollment.maximumRecords),
                ],
                [
                    'Manifest prefix bytes',
                    formatCount(registrationEnrollment.manifestPrefixBytes),
                ],
                [
                    'Maximum completed-enrollment manifest plaintext bytes',
                    formatCount(
                        registrationEnrollment.maximumEnrollmentManifestBytes,
                    ),
                ],
                [
                    'Maximum locked-proposal manifest plaintext bytes',
                    formatCount(
                        registrationEnrollment.maximumProposalIntentManifestBytes,
                    ),
                ],
                [
                    'Maximum manifest plaintext bytes',
                    formatCount(registrationEnrollment.maximumManifestBytes),
                ],
                [
                    'Maximum encrypted root bytes',
                    formatCount(registrationEnrollment.maximumRootBytes),
                ],
                [
                    'Recipient capsule associated-data bytes',
                    formatCount(
                        registrationEnrollment.recipientAssociatedBytes,
                    ),
                ],
                [
                    'Signing capsule associated-data bytes',
                    formatCount(registrationEnrollment.signingAssociatedBytes),
                ],
                [
                    'Root associated-data bytes',
                    formatCount(registrationEnrollment.rootAssociatedBytes),
                ],
                [
                    'Maximum restoration input bytes',
                    formatCount(
                        registrationEnrollment.maximumRestoreInputBytes,
                    ),
                ],
                [
                    'Maximum retained payload bytes',
                    formatCount(
                        registrationEnrollment.maximumRetainedPayloadBytes,
                    ),
                ],
                [
                    'Distinct initial root-key AES block inputs',
                    formatCount(
                        registrationEnrollment.initialRootDistinctBlockInputs,
                    ),
                ],
                [
                    'Maximum distinct AES block inputs per proposal root key',
                    formatCount(registrationEnrollment.rootDistinctBlockInputs),
                ],
                [
                    'Distinct signing-capsule AES block inputs',
                    formatCount(
                        registrationEnrollment.signingDistinctBlockInputs,
                    ),
                ],
            ],
        ),
        '',
    ];
};

export const renderSelectedOpeningTransformCensus = (): string[] => {
    const selectedOpeningTransform = compileSelectedOpeningTransformCensus();
    return [
        '## Selected opening transform census',
        '',
        'The forward transform follows only branches needed by the public opening indices. Bounds allow all selected indices to occupy one coset and count additions, subtractions, and scalar multiplications separately by the same branch ceiling. The full coefficient buffer, inverse transform, coset preparation, existing proof records, allocator overhead, and tree data remain additional. Index pairs use the scalar WebAssembly word width.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Transform length',
                    formatCount(selectedOpeningTransform.transformLength),
                ],
                [
                    'Maximum selected outputs in one coset',
                    formatCount(selectedOpeningTransform.maximumSelected),
                ],
                [
                    'Transform levels',
                    formatCount(selectedOpeningTransform.levels),
                ],
                [
                    'Full forward butterflies',
                    formatCount(selectedOpeningTransform.fullButterflies),
                ],
                [
                    'Maximum selected operations of each butterfly kind',
                    formatCount(
                        selectedOpeningTransform.maximumSelectedBranches,
                    ),
                ],
                [
                    'Maximum live selection-pair bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectionPairBytes,
                    ),
                ],
                [
                    'Maximum selection-index bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectionIndexBytes,
                    ),
                ],
                [
                    'Maximum selected base-output bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectedBaseOutputBytes,
                    ),
                ],
                [
                    'Maximum selected extension-output bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectedExtensionOutputBytes,
                    ),
                ],
            ],
        ),
        '',
    ];
};

export const renderSetupSelectionAndRegistrationBindingScreen =
    (): string[] => [
        '## Setup selection and registration binding screen',
        '',
        'The [selection model](../tests/setup-selection-model.ts) checks the fixed eligible pool, selected subset and quorum intersection. Its close-only counterexample keeps a valid ballot under one setup, enough honest pre-close holders and a closing quorum for another setup: the ciphertext cannot be retargeted. The [candidate analysis](private:preparation-analysis) owns that failure and the pre-ballot certification repair. These counts do not establish a construction or its security loss.',
        '',
        table(
            [
                'Participants',
                'Eligible',
                'Selected',
                'Quorum',
                'Minimum honest selected',
                'Minimum quorum intersection',
                'Possible selected sets',
            ],
            [3, 10, 20].map((participants) => {
                const value = compileSetupSelectionCensus(participants);
                return [
                    participants,
                    value.eligibleContributorCount,
                    value.setupContributorCount,
                    value.inventoryCertificateThreshold,
                    value.minimumHonestSelected,
                    value.minimumCertificateIntersection,
                    value.possibleSelectedSets,
                ].map(formatCount);
            }),
        ),
        '',
        'Candidate productive-stage upper bounds include registration, setup, an optional ballot and the existing close/target/release/outcome suffix. Same-stage restarts, status checks and organizer collection sessions add no nodes. The paths require the local coalescences in the [visit owner](private:preparation-stage-paths), complete retained payload availability and no additional participant-dependent output. They are conditional stage graphs, not emitted workflow measurements or a security verdict. Nonvoters may still perform setup before a later close intent and therefore share this conservative bound.',
        '',
        table(
            ['Candidate path', 'Participant stages', 'Organizer stages'],
            (['certified', 'recoverable-sealed'] as const).map((candidate) => [
                candidate,
                formatCount(
                    countStagePath(preparationStagePath(candidate, false)),
                ),
                formatCount(
                    countStagePath(preparationStagePath(candidate, true)),
                ),
            ]),
        ),
        '',
        'The [registration source model](../tests/registration-setup-binding-model.ts) enumerates each FHE modulus and common-sampler family permitted before roster fixing. Each family has an independent retained seed and four published auxiliary ciphertext polynomials that encrypt its original secret and first error. The source binding digest authenticates those ciphertexts under the poll, owner and family. Enrollment generates these auxiliary ciphertexts; it does not generate the FHE first public coordinates. The first-coordinate columns give their potential encoded sizes across the permitted families, separately from uploaded ciphertext bytes and retained seed bytes. None of these totals is a live-memory measurement.',
        '',
        table(
            [
                'Maximum participants / options',
                'FHE families',
                'Source binding digest payload bytes',
                'Private seed payload bytes',
                'Published source ciphertext bytes',
                'FHE first-coordinate bytes across families',
                'Largest FHE first-coordinate bytes',
                'Fixed auxiliary public pair bytes',
                'Auxiliary good-key phase error bound',
                'Auxiliary scale',
            ],
            [
                [3, 2],
                [10, 10],
                [20, 20],
            ].map(([participants, options]) => {
                const screen = compileRegistrationSetupBindingScreen(
                    participants,
                    options,
                );
                return [
                    `${participants} / ${options}`,
                    formatCount(screen.fhe.length),
                    formatCount(screen.sourceBindingDigestPayloadBytes),
                    formatCount(screen.privateSeedPayloadBytes),
                    formatCount(screen.sourceCiphertextPayloadBytes),
                    formatCount(screen.generatedPublicCoordinateBytes),
                    formatCount(screen.largestPublicCoordinateBytes),
                    formatCount(screen.auxiliary.fixedPublicPairBytes),
                    formatCount(screen.auxiliary.goodKeyPhaseError),
                    formatCount(screen.auxiliary.scale),
                ];
            }),
        ),
        '',
        'The auxiliary good-key bound is `(2*h_aux+1)*E`, and twice this value must be strictly below its scale. Fixed-suite sampling and initialization, global auxiliary-key reuse, encrypted-source hybrids, adaptive selection, proof soundness and the complete original credential population have their separate charges in the composed ledger.',
        '',
        '### FHE key source generation screen',
        '',
        'The [source screen model](../tests/fhe-key-source-resource-model.ts) counts one full-ring original source and its reconstruction into the first contribution gadget. It retains a fixed synthetic seed, public digest and bounded samples between phases; no complete public coordinate or private source survives the phase transition. The source phase includes its retained sparse/error vectors, temporary sparse transform, first-key word columns, public/native-check working vectors and allocation allowance. Continuation conservatively reuses the existing complete contribution-generation allowance plus the retained first-key error. The separate reference phase uses direct sparse BigInt convolution at fixed coordinates. These are phase planning allowances, not measured peaks, a complete registration or a proof-generation bound.',
        '',
        table(
            ['Source-screen property', 'Value'],
            (() => {
                const screen = compileFheKeySourceScreenResources();
                return [
                    ['Participants', screen.participantCount],
                    ['Options', screen.optionCount],
                    ['Ring degree', screen.degree],
                    [
                        'Signed public coefficient bytes',
                        screen.coefficientBytes,
                    ],
                    ['Common coefficient sample bits', screen.commonSampleBits],
                    [
                        'Independent coordinate samples',
                        screen.samplePositions.length,
                    ],
                    ['Canonical report bytes', screen.reportBytes],
                    ['Output capacity bytes', screen.outputCapacity],
                    [
                        'Original private source payload bytes',
                        screen.sourcePayloadBytes,
                    ],
                    [
                        'First-key word-column payload bytes',
                        screen.keyWitnessBytes,
                    ],
                    [
                        'Source generation phase allowance bytes',
                        screen.sourcePhaseBytes,
                    ],
                    [
                        'First-gadget continuation phase allowance bytes',
                        screen.continuationPhaseBytes,
                    ],
                    [
                        'Independent reference phase allowance bytes',
                        screen.referencePhaseBytes,
                    ],
                    [
                        'Native operation planning bytes',
                        screen.nativePlanningBytes,
                    ],
                    [
                        'Scalar operation planning bytes',
                        screen.scalarPlanningBytes,
                    ],
                ].map(([label, value]) => [
                    String(label),
                    formatCount(value as number | bigint),
                ]);
            })(),
        ),
        '',
    ];

const renderCommittedOfferResources = (): string[] => {
    const profiles = [
        deriveSupportedProfile(3, 2),
        completionProfile(),
        largestSupportedProfile(),
    ];
    const all = listSupportedProfiles().map((profile) => ({
        profile,
        preparation: compilePreparationResources(profile),
    }));
    return [
        '## Committed offers and published aggregates',
        '',
        'The public coefficient oracle and aggregate evaluation proofs use the unchanged profile family. The selector re-encodes complete offers and publishes every aggregate dependency before endorsement. Logical transfer bounds include publication receipts, cached-prefix replay and additional organizer calls; they exclude unbounded hostile candidates and arbitrary restarts. Expanded oracle bytes are total materialized evaluation data, not simultaneous memory. Collection storage counts disposable logical payload, excluding other custody, database journals and garbage collection.',
        '',
        table(
            [
                'Profile',
                'Public columns',
                'Expanded public oracle bytes',
                'Generated sum bytes',
                'Maximum accepted sum bytes',
                'Evaluation proof maximum bytes',
                'Collection cache peak bytes',
                'Organizer calls',
                'Largest organizer call protocol allowance',
            ],
            profiles.map((profile) => {
                const value = compileCommittedOfferCensus(profile),
                    resources = compilePreparationResources(profile),
                    cache = compileSetupAggregateResources(profile);
                return [
                    `${profile.participantCount}/${profile.optionCount}`,
                    ...[
                        value.committedColumns,
                        value.publicOracleBytes,
                        value.generatedAggregateBytes,
                        value.maximumAggregateBytes,
                        value.maximumEvaluationProofBytes,
                        cache.maximumCollectionPayloadBytes,
                        resources.organizerSchedule.calls.length,
                        resources.organizerSchedule.calls.reduce(
                            (maximum, bytes) =>
                                bytes > maximum ? bytes : maximum,
                            0n,
                        ),
                    ].map(formatCount),
                ];
            }),
        ),
        '',
        table(
            ['Completion-profile proof operand', 'Value'],
            (() => {
                const value = compileCommittedOfferCensus(completionProfile()),
                    hash =
                        compilePublicEvaluationHashCensus(completionProfile());
                return [
                    ['Column degree', value.columnDegree],
                    [
                        'Evaluation quotient degree',
                        value.evaluationQuotientDegree,
                    ],
                    [
                        'Degree-shift identity degree',
                        value.degreeShiftIdentityDegree,
                    ],
                    ['Common agreement points', value.agreementPoints],
                    [
                        'Accepted digit magnitude bound',
                        value.committedDigitMagnitudeBound,
                    ],
                    [
                        'Accepted sum magnitude bound',
                        value.aggregateLimbMagnitudeBound,
                    ],
                    [
                        'Generated signed limb bytes',
                        value.generatedAggregateLimbBytes,
                    ],
                    [
                        'Maximum signed limb bytes',
                        value.maximumAggregateLimbBytes,
                    ],
                    ['Evaluation query pairs', value.evaluationQueries],
                    ['Evaluation folds', value.evaluationFolds],
                    ['Evaluation header bytes', value.evaluationHeaderBytes],
                    [
                        'Evaluation verifier message bytes',
                        value.evaluationMessageBytes,
                    ],
                    [
                        'Evaluation weighted-fold numerator',
                        value.weightedFri.upper.numerator,
                    ],
                    [
                        'Evaluation weighted-fold denominator',
                        value.weightedFri.upper.denominator,
                    ],
                    ['Evaluation prover tree queries', hash.proverTreeQueries],
                    [
                        'Evaluation verifier queries',
                        hash.maximumVerifierQueries,
                    ],
                ].map(([name, count]) => [
                    String(name),
                    formatCount(count as bigint | number),
                ]);
            })(),
        ),
        '',
        table(
            ['Across all supported profiles', 'Count'],
            [
                [
                    'Participant preparation above planning',
                    all.filter(
                        ({ preparation }) =>
                            !preparation.preparationDownloadWithinPlanning,
                    ).length,
                ],
                [
                    'Organizer stage above planning',
                    all.filter(
                        ({ preparation }) =>
                            !preparation.organizerDownloadWithinPlanning,
                    ).length,
                ],
                [
                    'Maximum organizer calls',
                    Math.max(
                        ...all.map(
                            ({ preparation }) =>
                                preparation.organizerSchedule.calls.length,
                        ),
                    ),
                ],
                [
                    'Organizer calls above reserved protocol budget',
                    all.filter(({ preparation }) =>
                        preparation.organizerSchedule.calls.some(
                            (bytes) =>
                                bytes > preparation.organizerSchedule.budget,
                        ),
                    ).length,
                ],
            ].map(([name, count]) => [
                String(name),
                formatCount(count as number),
            ]),
        ),
        '',
    ];
};

export const renderSetupSelectionWireAndResources = (): string[] => {
    const completion = completionProfile();
    const selectionWires = compileSupportedThresholdCompletionProfiles().map(
        (profile) => compileSetupSelectionWireCensus(profile.participantCount),
    );
    const preparationResources = compilePreparationResources(completion);
    return [
        ...renderCommittedOfferResources(),
        '## Setup selection wire and resources',
        '',
        'Offers authenticate complete ordinary body identities under the original roster and author. Exactly the roster-derived selected count enters the canonical proposal, and exactly the inventory quorum signs its certificate. Different valid signer subsets carry the same semantic setup identity. Whole-body commitments, later opening messages and unanimous confirmation carriers are absent. The independent lifecycle model covers own-work coexistence, one-shot endorsements, original-state restoration and authenticated retirement; it assumes the complete owning proof/signature verifiers and the named published-store retention contract.',
        '',
        table(
            [
                'Participants',
                'Eligible',
                'Selected',
                'Quorum',
                'Offer envelope bytes',
                'Selection body bytes',
                'Endorsement body bytes',
                'Endorsement packet bytes',
                'Certificate bytes',
            ],
            selectionWires.map((wire) =>
                [
                    wire.participantCount,
                    wire.eligibleContributorCount,
                    wire.setupContributorCount,
                    wire.inventoryCertificateThreshold,
                    wire.offerEnvelopeBytes,
                    wire.selectionBodyBytes,
                    wire.endorsementBodyBytes,
                    wire.endorsementPacketBytes,
                    wire.certificateBytes,
                ].map(formatCount),
            ),
        ),
        '',
        table(
            ['Completion-profile component', 'Value'],
            [
                [
                    'Maximum eligible body corpus bytes',
                    formatCount(preparationResources.maximumEligibleBodyBytes),
                ],
                [
                    'Maximum selected body corpus bytes',
                    formatCount(preparationResources.maximumSelectedBodyBytes),
                ],
                [
                    'Maximum eligible signed-offer corpus bytes',
                    formatCount(preparationResources.maximumEligibleOfferBytes),
                ],
                [
                    'Maximum certified setup payload bytes',
                    formatCount(
                        preparationResources.maximumCertifiedSetupBytes,
                    ),
                ],
                [
                    'Maximum endorsement packet corpus bytes',
                    formatCount(
                        preparationResources.maximumEndorsementPacketBytes,
                    ),
                ],
                [
                    'Maximum offer proofs',
                    formatCount(preparationResources.maximumOfferProofs),
                ],
                [
                    'Maximum untrusted discovery page bytes',
                    formatCount(preparationResources.maximumDiscoveryPageBytes),
                ],
                [
                    'Maximum generation and continuation seeds',
                    formatCount(
                        preparationResources.maximumGenerationAndContinuationSeeds,
                    ),
                ],
                [
                    'Selected proof verifications per fresh reader',
                    formatCount(
                        preparationResources.selectedProofVerificationsPerReader,
                    ),
                ],
                [
                    'Fresh selected-offer verification read bytes',
                    formatCount(
                        preparationResources.maximumOfferVerificationReadBytes,
                    ),
                ],
                [
                    'Organizer selected polynomial aggregation reread bytes',
                    formatCount(
                        preparationResources.selectedPolynomialRereadBytes,
                    ),
                ],
                [
                    'Exact proof lookahead bytes',
                    formatCount(
                        preparationResources.selectedProofLookaheadBytes,
                    ),
                ],
                [
                    'Proof lookahead transport reservation bytes',
                    formatCount(
                        preparationResources.maximumLookaheadIngressBytes,
                    ),
                ],
                [
                    'Matching retained-input certificate activation read bytes',
                    formatCount(
                        preparationResources.maximumMatchingCertificateActivationReadBytes,
                    ),
                ],
                [
                    'Fresh certificate activation read bytes',
                    formatCount(
                        preparationResources.maximumFreshCertificateActivationReadBytes,
                    ),
                ],
                [
                    'Clean preparation logical download bytes',
                    formatCount(
                        preparationResources.maximumCleanPreparationDownloadBytes,
                    ),
                ],
                [
                    'Clean organizer preparation logical download bytes',
                    formatCount(
                        preparationResources.maximumCleanOrganizerPreparationDownloadBytes,
                    ),
                ],
                [
                    'Clean preparation participant upload bytes',
                    formatCount(
                        preparationResources.maximumCleanParticipantUploadBytes,
                    ),
                ],
                [
                    'Clean preparation total upload bytes',
                    formatCount(
                        preparationResources.maximumCleanTotalUploadBytes,
                    ),
                ],
                [
                    'Transfer planning target bytes',
                    formatCount(preparationResources.transferPlanningBytes),
                ],
                [
                    'Preparation download planning margin bytes',
                    formatCount(
                        preparationResources.transferPlanningBytes -
                            preparationResources.maximumCleanPreparationDownloadBytes,
                    ),
                ],
                [
                    'Organizer preparation download planning margin bytes',
                    formatCount(
                        preparationResources.transferPlanningBytes -
                            preparationResources.maximumCleanOrganizerPreparationDownloadBytes,
                    ),
                ],
                [
                    'Participant upload planning margin bytes',
                    formatCount(
                        preparationResources.transferPlanningBytes -
                            preparationResources.maximumCleanParticipantUploadBytes,
                    ),
                ],
                [
                    'Total upload planning margin bytes',
                    formatCount(
                        preparationResources.transferPlanningBytes -
                            preparationResources.maximumCleanTotalUploadBytes,
                    ),
                ],
                [
                    'Volatile offer polynomial-identity payload bytes',
                    formatCount(
                        preparationResources.volatileOfferPolynomialIdentityBytes,
                    ),
                ],
            ],
        ),
        '',
        'Fresh participants verify the selected compact offers, their registered source families and the published aggregate with its per-offer evaluation proofs. Organizer discovery verifies and collects the full selected polynomials into bounded local storage, publishes the aggregate, creates and verifies its per-offer evaluation proofs, and rereads the aggregate before signing the selection. A matching original selection reference avoids another proof pass at activation; losing or absent local endorsement uses the fresh certificate path. Complete exact named reads with owning verification establish publication under the monotone public-store premise, so selected bodies are not uploaded again. Each extra cache miss or restart must charge its actual verification and collection work; there is no finite lifetime count. These preparation-only logical payload margins exclude the other workflow phases and browser bootstrap and therefore do not establish complete-action qualification.',
        '',
        'The following preparation screen charges selected-offer collection, committed-polynomial reads for the evaluation proofs, aggregate publication and verification reads, every eligible discovery page, and the repeated roster prelude and completed-proof verification on continuation calls. All organizer collection calls belong to one stage. Polynomial-only floors exclude proofs and metadata. Transfer overruns remain unaccepted obligations under the runtime planning rule; the variance ceiling is not an absolute cryptographic or allocation limit.',
        '',
        table(
            [
                'Profile',
                'Participant polynomial-read floor',
                'Participant logical-download maximum',
                'Organizer polynomial-read floor',
                'Organizer logical-download maximum',
                'Participant upload maximum',
                'Total upload maximum',
                'Eligible polynomial-upload floor',
                'Planning variance ceiling',
            ],
            [
                [10, 10],
                [20, 20],
            ].map(([participants, options]) => {
                const value = compilePreparationResources(
                    deriveSupportedProfile(participants, options),
                );
                return [
                    participants + '/' + options,
                    ...[
                        value.cleanParticipantPolynomialReadFloorBytes,
                        value.maximumCleanPreparationDownloadBytes,
                        value.cleanOrganizerPolynomialReadFloorBytes,
                        value.maximumCleanOrganizerPreparationDownloadBytes,
                        value.maximumCleanParticipantUploadBytes,
                        value.maximumCleanTotalUploadBytes,
                        value.completeEligiblePolynomialUploadFloorBytes,
                        value.planningVarianceCeilingBytes,
                    ].map(formatCount),
                ];
            }),
        ),
        '',
    ];
};

export const renderRosterProposalCensus = (): string[] => {
    const rosterProposals = compileSupportedThresholdCompletionProfiles().map(
        (profile) => compileRosterProposalCensus(profile.participantCount),
    );
    return [
        '## Roster proposal census',
        '',
        'The proposal binds the ordered complete registration-body identities under an authenticated poll. Its public corpus includes every recipient key, registered source ciphertext body, registration header and signature, and one signed poll definition. The contribution generator consumes the verified records directly and has no caller-supplied key-digest carrier. Retained payload counts exclude allocator and verifier scratch. These public input records do not supply organizer authorization or participant confirmation.',
        '',
        table(
            [
                'Participants',
                'Proposal bytes',
                'Contribution role bytes',
                'Retained recipient-key bytes',
                'Retained record payload bytes',
                'Maximum public corpus bytes',
            ],
            rosterProposals.map((proposal) => [
                String(proposal.participantCount),
                formatCount(proposal.proposalBytes),
                formatCount(proposal.roleBytes),
                formatCount(proposal.retainedRecipientKeyBytes),
                formatCount(proposal.retainedRecordPayloadBytes),
                formatCount(proposal.maximumPublicCorpusBytes),
            ]),
        ),
        '',
    ];
};
