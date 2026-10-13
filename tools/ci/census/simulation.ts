import { compileSimulatorKeyKnowledgeCensus } from '#tests/simulator-key-knowledge-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';
import type { CensusInputs } from '#tools/ci/census/inputs.js';

export const renderSimulatorRecipientKeyAvailability = (): string[] => [
    '## Simulator recipient-key availability',
    '',
    'An encryption reduction with one unknown honest recipient key uses other honest recipient keys for corrupt-contribution interpolation. These are combinatorial availability counts only; the actual sharing scheme, decryption correctness and ciphertext/proof contracts remain separate. More than one unknown key is not silently assumed to satisfy the same count.',
    '',
    table(
        [
            'Participants',
            'Corruption bound',
            'Required evaluations',
            'Known honest keys with one challenge',
            'Maximum unknown honest keys from the count alone',
        ],
        compileSimulatorKeyKnowledgeCensus().map((value) => [
            formatCount(value.participants),
            formatCount(value.faults),
            formatCount(value.threshold),
            formatCount(value.knownHonestWithOneChallenge),
            formatCount(value.maximumUnknownHonestKeys),
        ]),
    ),
    '',
];

export const renderCommitmentEquivocationFiniteModel = ({
    commitmentEquivocation,
    commitmentPrefix,
    duplicateCommitmentInputs,
}: Pick<
    CensusInputs,
    'commitmentEquivocation' | 'commitmentPrefix' | 'duplicateCommitmentInputs'
>): string[] => [
    '## Commitment equivocation finite model',
    '',
    'The finite model compares exact joint density matrices conditioned on the complete post-opening oracle and public transcript. Its alternate constructions test incomplete masking, retained shadow values, and unwanted changes to the uncommitted output suffix. This enumerates selected receivers rather than proving quantum security.',
    '',
    table(
        ['Property', 'Value'],
        [
            [
                'Full-message real cases',
                formatCount(commitmentEquivocation.realCases),
            ],
            [
                'Full-message simulated cases',
                formatCount(commitmentEquivocation.simulatedCases),
            ],
            [
                'Full-message classical blocks',
                formatCount(commitmentEquivocation.classicalBlocks),
            ],
            [
                'Full-message differing entries',
                formatCount(commitmentEquivocation.differingEntries),
            ],
            [
                'Prefix-programming simulated cases',
                formatCount(commitmentPrefix.simulatedCases),
            ],
            [
                'Prefix-programming differing entries',
                formatCount(commitmentPrefix.differingEntries),
            ],
            [
                'Duplicate-input distinguishing events',
                formatCount(duplicateCommitmentInputs.simulatedEvents),
            ],
            [
                'Duplicate-input simulated cases',
                formatCount(duplicateCommitmentInputs.simulatedCases),
            ],
        ],
    ),
    '',
];
