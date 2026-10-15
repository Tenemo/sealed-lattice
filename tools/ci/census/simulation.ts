import { compileSimulatorKeyKnowledgeCensus } from '#tests/simulator-key-knowledge-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';

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
