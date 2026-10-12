import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { deriveSetupContributionShape } from '#tests/setup-contribution-relation-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';
import {
    formatCount,
    table,
    distinctJoined,
    rangeOf,
} from '#tools/ci/census/format.js';
import type { CensusInputs } from '#tools/ci/census/inputs.js';

export const renderSetupContributionOperatorCensus = ({
    setupRelation,
}: Pick<CensusInputs, 'setupRelation'>): string[] => [
    '## Setup contribution operator census',
    '',
    'The complete reduced-ring model exercises the FHE key, encrypted-share, range and support relations. Full-profile affine rows scale those same equation families to the full ring degree. The full-degree KLSW auxiliary secret remains part of setup; the fixed auxiliary ballot pair supplies no setup secret, equation, column or public polynomial.',
    '',
    table(
        ['Property', 'Value'],
        [
            ['Word columns', formatCount(setupRelation.wordColumns)],
            ['Boolean columns', formatCount(setupRelation.booleanColumns)],
            [
                'Additional narrow-error memberships',
                formatCount(setupRelation.errorColumns),
            ],
            [
                'Disjoint positive/negative pairs',
                formatCount(setupRelation.disjointPairs),
            ],
            ['Exact support-sum rows', formatCount(setupRelation.supportRows)],
            ['Full-profile affine rows', formatCount(setupRelation.affineRows)],
            [
                'Single-entry inverse columns',
                formatCount(setupRelation.lookupEntries),
            ],
            [
                'Full resident affine coefficient bytes',
                formatCount(setupRelation.fullAffineCoefficientByteLength),
            ],
            [
                'One public adjoint coefficient vector bytes',
                formatCount(
                    setupRelation.singlePublicAdjointCoefficientByteLength,
                ),
            ],
            [
                'Largest signed public polynomial bytes',
                formatCount(setupRelation.largestPublicPolynomialByteLength),
            ],
            [
                'Maximum public polynomial query points',
                formatCount(setupRelation.maximumPublicQueryCount),
            ],
            [
                'One public polynomial query-value bytes',
                formatCount(setupRelation.publicQueryValueByteLength),
            ],
            [
                'All affine coefficients at query points bytes',
                formatCount(setupRelation.fullAffineQueryValueByteLength),
            ],
            [
                'Query-transform vectors and twiddles bytes',
                formatCount(setupRelation.publicQueryTransformVectorByteLength),
            ],
            [
                'Full-ring query cosets',
                formatCount(setupRelation.fullRingQueryCosets),
            ],
            [
                'Expanded statement polynomials',
                formatCount(setupRelation.expandedStatementPolynomialCount),
            ],
            [
                'Expanded statement header bytes',
                formatCount(setupRelation.expandedStatementHeaderByteLength),
            ],
            [
                'Expanded statement bytes',
                formatCount(setupRelation.expandedStatementByteLength),
            ],
            [
                'Maximum encoded queried-operator bytes',
                formatCount(setupRelation.maximumEncodedOperatorByteLength),
            ],
            [
                'Maximum exact integer limb-convolution magnitude',
                formatCount(
                    setupRelation.maximumIntegerLimbConvolutionMagnitude,
                ),
            ],
            [
                'Synthetic witness header bytes',
                formatCount(setupRelation.syntheticWitnessHeaderByteLength),
            ],
            [
                'Synthetic witness bytes',
                formatCount(setupRelation.syntheticWitnessByteLength),
            ],
        ],
    ),
    '',
    'The query-transform subtotal includes the coefficient and scratch vectors, one base-field twiddle table, and the queried output vector. It excludes input chunks, parser records, query-index groups, allocator behavior, stack, JavaScript, and the rest of proof verification. The experimental expanded statement repeats common matrices and recipient public keys in the verifier input; its length is not the contributor upload size. The encoded operator includes the statement digest, target, final row weight, and queried coefficients.',
    '',
];

export const renderExactRNSArithmeticCensus = ({
    rnsArithmetic,
}: Pick<CensusInputs, 'rnsArithmetic'>): string[] => [
    '## Exact RNS arithmetic census',
    '',
    "The recursive-context floor comes from the pinned library allocation structure. The alternative uses flat scalar transform plans and sufficiently wide auxiliary integer residues, then exact CRT lifting and rounding under the existing cryptographic modulus. The evaluation's working storage holds the transformed key records; scheduled ciphertexts remain a separate live-set cost.",
    '',
    table(
        ['Property', 'Value'],
        [
            ['Polynomial degree', formatCount(rnsArithmetic.degree)],
            [
                'Base primes in the wrapper screen',
                formatCount(rnsArithmetic.basePrimes),
            ],
            [
                'Extended primes in the wrapper screen',
                formatCount(rnsArithmetic.multiplicationPrimes),
            ],
            [
                'Pinned library transform-table bytes per prime',
                formatCount(rnsArithmetic.tableBytesPerPrime),
            ],
            [
                'Recursive extended-context transform tables alone',
                formatCount(rnsArithmetic.recursiveTableBytes),
            ],
            [
                'Auxiliary primes for exact integer products',
                formatCount(rnsArithmetic.exactProductPrimes),
            ],
            [
                'Flat transform-plan table bytes per prime',
                formatCount(rnsArithmetic.flatTableBytesPerPrime),
            ],
            [
                'Flat transform-table bytes',
                formatCount(rnsArithmetic.flatTableBytes),
            ],
            [
                'Machine words per canonical cryptographic coefficient',
                formatCount(rnsArithmetic.coefficientWords),
            ],
            [
                'Canonical polynomial working bytes',
                formatCount(rnsArithmetic.canonicalPolynomialBytes),
            ],
            [
                "Stored records of a multiplication's keys",
                formatCount(rnsArithmetic.multiplicationKeyRecordBytes),
            ],
        ],
    ),
    '',
];

export const renderFixedModulusBFVNoiseCensus = ({
    fixedModulusBfv,
}: Pick<CensusInputs, 'fixedModulusBfv'>): string[] => [
    '## Fixed-modulus BFV noise census',
    '',
    'Exact worst-case noise screen for the uniform comparison and duplicated ranking-window candidate. The full integer tensor-rounding and KLSW relinearization equations are checked independently. This screen does not establish the circular-key assumption, complete proof compiler, browser cost, or protocol admission.',
    '',
    table(
        ['Property', 'Value'],
        [
            ['Participants', formatCount(fixedModulusBfv.participantCount)],
            ['Options', formatCount(fixedModulusBfv.optionCount)],
            [
                'Ciphertext polynomial degree',
                formatCount(fixedModulusBfv.polynomialDegree),
            ],
            [
                'Plaintext subring degree',
                formatCount(fixedModulusBfv.plaintextSubringDegree),
            ],
            [
                'Plaintext modulus',
                formatCount(fixedModulusBfv.plaintextModulus),
            ],
            [
                'Ciphertext modulus',
                formatCount(fixedModulusBfv.ciphertextModulus),
            ],
            ['Release modulus', formatCount(fixedModulusBfv.releaseModulus)],
            [
                'Per-contributor secret support weight',
                formatCount(fixedModulusBfv.secretSupportWeight),
            ],
            [
                'Accepted error magnitude bound',
                formatCount(fixedModulusBfv.errorBound),
            ],
            ['Gadget base', formatCount(fixedModulusBfv.gadgetBase)],
            ['Gadget coordinates', formatCount(fixedModulusBfv.gadgetLength)],
            [
                'Comparison block width',
                formatCount(fixedModulusBfv.comparisonBlockWidth),
            ],
            [
                'Ciphertext multiplications',
                formatCount(fixedModulusBfv.multiplications),
            ],
            ['Ciphertext additions', formatCount(fixedModulusBfv.additions)],
            [
                'Scalar plaintext products',
                formatCount(fixedModulusBfv.scalarProducts),
            ],
            [
                'Vector plaintext products',
                formatCount(fixedModulusBfv.plaintextProducts),
            ],
            ['Unit rotations', formatCount(fixedModulusBfv.rotations)],
            [
                'Separately rounded tensor-coordinate products',
                formatCount(fixedModulusBfv.tensorProducts),
            ],
            [
                'Relinearization external products',
                formatCount(fixedModulusBfv.relinearizationExternalProducts),
            ],
            [
                'Relinearization gadget decompositions',
                formatCount(
                    fixedModulusBfv.relinearizationGadgetDecompositions,
                ),
            ],
            [
                'Rotation external products including the common vector',
                formatCount(fixedModulusBfv.rotationExternalProducts),
            ],
            [
                'Rotation gadget decompositions',
                formatCount(fixedModulusBfv.rotationGadgetDecompositions),
            ],
            [
                'Total polynomial products inside gadget external products',
                formatCount(fixedModulusBfv.gadgetPolynomialProducts),
            ],
            [
                'Final modulus-switch coefficient roundings',
                formatCount(fixedModulusBfv.finalModulusSwitchCoefficients),
            ],
            [
                'Plaintext additions',
                formatCount(fixedModulusBfv.plaintextAdditions),
            ],
            [
                'Comparison multiplicative depth',
                formatCount(fixedModulusBfv.comparisonDepth),
            ],
            [
                'Ranking multiplicative depth',
                formatCount(fixedModulusBfv.rankingDepth),
            ],
            [
                'Comparison error bound bits',
                formatCount(fixedModulusBfv.comparisonErrorBits),
            ],
            [
                'Ranking error bound bits',
                formatCount(fixedModulusBfv.rankingErrorBits),
            ],
            [
                'Error after final modulus switch',
                formatCount(fixedModulusBfv.releaseError),
            ],
            [
                'Signed uniform release-noise bits',
                formatCount(fixedModulusBfv.releaseNoiseBits),
            ],
            [
                'Statistical target bits',
                formatCount(fixedModulusBfv.statisticalBits),
            ],
            [
                'Joint translated-cube bound holds',
                fixedModulusBfv.jointStatisticalBoundHolds ? 'yes' : 'no',
            ],
            [
                'Complete release correctness inequality holds',
                fixedModulusBfv.releaseCorrect ? 'yes' : 'no',
            ],
            [
                'Public key-contribution corpus bytes before sharing and proofs',
                formatCount(fixedModulusBfv.publicKeyCorpusBytes),
            ],
        ],
    ),
    '',
];

export const renderSupportedProfileCensus = ({
    supportedProfiles,
    fixedModulusBfv,
    contributionBodies,
    publicCorpusVarianceCeiling,
    countsAbove,
}: Pick<
    CensusInputs,
    | 'supportedProfiles'
    | 'fixedModulusBfv'
    | 'contributionBodies'
    | 'publicCorpusVarianceCeiling'
    | 'countsAbove'
>): string[] => [
    '## Supported profile census',
    '',
    'Parameters of every supported participant and option count under the derivation rules owned by the security argument. Thresholds come from the threshold completion rules; the interpolation norms are exact maxima over every subset; each share-lifting width is the widest sound limb; the ciphertext and release moduli are the smallest lengths of the fixed prime form that decode the ranking graph and satisfy the flooded release and its lifting. These are arithmetic derivations, not attack estimates, resource bounds, an implementation or admission.',
    '',
    table(
        [
            'Participants',
            'Corrupt bound',
            'Inventory threshold',
            'Release threshold',
            'Minimum turnout',
            'Interpolation ring degree',
            'Clearing factor',
            'Scaled reconstruction one-norm',
            'Simulation one-norm',
            'Joint simulation sum',
            'Sharing coefficient bits',
            'Share limb bits',
            'Share carry bits',
            'Release share bits',
            'Release quotient bits',
        ],
        supportedProfiles.profiles.map((row) => {
            const [first] = row;
            return [
                formatCount(first.participantCount),
                formatCount(first.maximumCorruptParticipantCount),
                formatCount(first.inventoryCertificateThreshold),
                formatCount(first.releaseThreshold),
                formatCount(first.minimumTurnout),
                formatCount(first.interpolation.interpolationRingDegree),
                formatCount(first.interpolation.clearingFactor),
                formatCount(
                    first.interpolation.maximumScaledReconstructionOneNorm,
                ),
                formatCount(first.interpolation.maximumSimulationOneNorm),
                formatCount(
                    first.interpolation.maximumJointSimulationOneNormSum,
                ),
                formatCount(first.shareLifting.sharingCoefficientBits),
                formatCount(first.shareLifting.limbBits),
                formatCount(first.shareLifting.carryBits),
                distinctJoined(
                    row.map((profile) => profile.releaseLifting.shareBits),
                ),
                distinctJoined(
                    row.map((profile) => profile.releaseLifting.quotientBits),
                ),
            ];
        }),
    ),
    '',
    'Ciphertext modulus bits by participant count (rows) and option count (columns):',
    '',
    table(
        [
            'Participants',
            ...supportedProfiles.optionCounts.map((count) => String(count)),
        ],
        supportedProfiles.profiles.map((row) => [
            formatCount(row[0].participantCount),
            ...row.map((profile) => formatCount(profile.ciphertext.bits)),
        ]),
    ),
    '',
    table(
        [
            'Modulus',
            'Bits',
            'Odd factor over the plaintext modulus',
            'Proth witness',
            'Gadget coordinates',
            'Profiles',
        ],
        [
            ...supportedProfiles.ciphertextModuli.map((prime) => [
                'Ciphertext',
                formatCount(prime.bits),
                formatCount(prime.oddFactor / fixedModulusBfv.plaintextModulus),
                formatCount(prime.witness),
                formatCount(prime.gadgetLength),
                formatCount(prime.profileCount),
            ]),
            ...supportedProfiles.releaseModuli.map((prime) => [
                'Release',
                formatCount(prime.bits),
                formatCount(prime.oddFactor / fixedModulusBfv.plaintextModulus),
                formatCount(prime.witness),
                'none',
                formatCount(supportedProfiles.profiles.flat().length),
            ]),
        ],
    ),
    '',
    table(
        ['Property', 'Value'],
        [
            [
                'Supported profiles',
                formatCount(supportedProfiles.profiles.flat().length),
            ],
            [
                'Smallest ciphertext modulus bits',
                formatCount(supportedProfiles.minimumCiphertextModulusBits),
            ],
            [
                'Largest ciphertext modulus bits',
                formatCount(supportedProfiles.maximumCiphertextModulusBits),
            ],
            [
                'Release-noise bits range',
                supportedProfiles.releaseNoiseBitRange
                    .map((value) => formatCount(value))
                    .join(' to '),
            ],
            [
                'Largest ranking multiplicative depth',
                formatCount(supportedProfiles.maximumRankingDepth),
            ],
            [
                'Largest ranking error bound bits',
                formatCount(supportedProfiles.maximumRankingErrorBits),
            ],
            [
                'Smallest release correctness margin bits, rounded down',
                `\`${(Number(supportedProfiles.tightestRelease.marginHundredths) / 100).toFixed(2)}\` at ${formatCount(supportedProfiles.tightestRelease.participantCount)} participants and ${formatCount(supportedProfiles.tightestRelease.optionCount)} options`,
            ],
            [
                'Profiles with a release correctness margin under one bit',
                formatCount(supportedProfiles.releaseMarginsUnderOneBit),
            ],
        ],
    ),
    '',
    'Proof and body layouts of every supported profile under the same derivation rules. Each cell is the range over the option counts of one participant count.',
    '',
    table(
        [
            'Participants',
            'FHE common-matrix sample bits',
            'Setup word columns',
            'Setup affine rows',
            'Verifier message bytes',
            'Largest contribution body bytes',
            'All contribution body bytes',
            'Largest ballot body bytes',
        ],
        supportedProfiles.profiles.map((row, index) => [
            formatCount(row[0].participantCount),
            rangeOf(
                row.map(
                    (profile) =>
                        compileCommonMatrixSamplingCensus(profile)
                            .fheBitsPerCoefficient,
                ),
            ),
            rangeOf(
                row.map(
                    (profile) =>
                        deriveSetupContributionShape(profile).wordColumns,
                ),
            ),
            rangeOf(
                row.map(
                    (profile) =>
                        deriveSetupContributionShape(profile).affineRows,
                ),
            ),
            rangeOf(
                row.map(
                    (profile) =>
                        compileWideChallengeCompilerCensus(profile)
                            .challengeBytes,
                ),
            ),
            rangeOf(
                contributionBodies[index].map((body) => body.maximumBodyBytes),
            ),
            rangeOf(
                contributionBodies[index].map(
                    (body) => body.maximumEligibleOfferBodies,
                ),
            ),
            rangeOf(
                row.map(
                    (profile) =>
                        compileBallotBodyCensus(profile).maximumBodyBytes,
                ),
            ),
        ]),
    ),
    '',
    'Only the first `d` roster positions contribute to the setup. Every participant verifies all contributions of its roster. The mobile runtime sets the public corpus variance ceiling fifty percent above its planning target. A participant count is listed when some option count exceeds the ceiling.',
    '',
    table(
        ['Property', 'Value'],
        [
            [
                'Public corpus variance ceiling',
                formatCount(publicCorpusVarianceCeiling),
            ],
            [
                'Participant counts whose contributions exceed the variance ceiling',
                countsAbove(publicCorpusVarianceCeiling),
            ],
        ],
    ),
    '',
];
