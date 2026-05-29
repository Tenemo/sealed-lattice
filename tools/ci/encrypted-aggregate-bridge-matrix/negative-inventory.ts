export type NegativeInventorySurface =
    | 'matrix-cheap'
    | 'matrix-sentinel'
    | 'protocol-structure'
    | 'rust-wasm-verifier'
    | 'sdk-verifier';

export type NegativeInventoryStatus = 'covered' | 'partial' | 'pending';

export type NegativeInventoryItem = {
    readonly id: string;
    readonly description: string;
    readonly designNoteSource: 'internal bridge negative-coverage section';
    readonly requiredSurfaces: readonly NegativeInventorySurface[];
    readonly status: NegativeInventoryStatus;
};

export const negativeInventory: readonly NegativeInventoryItem[] = [
    {
        description:
            'Wrong aggregate derivation component, aggregate-share commitment, aggregate subproof summary, hidden aggregate share, opening, reduction, or quotient bound must reject.',
        id: 'aggregate-relation-binding',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['matrix-sentinel', 'rust-wasm-verifier'],
        status: 'covered',
    },
    {
        description:
            'Wrong BGV batch layout, encoded coordinate order, profile hash, layout hash, or top-k evaluator input layout must reject.',
        id: 'layout-and-profile-binding',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: [
            'matrix-cheap',
            'matrix-sentinel',
            'protocol-structure',
            'rust-wasm-verifier',
        ],
        status: 'covered',
    },
    {
        description:
            'Scalar-only layout, permuted one-hot buckets, and missing score buckets must reject.',
        id: 'score-layout-negatives',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['matrix-cheap', 'rust-wasm-verifier'],
        status: 'covered',
    },
    {
        description:
            'Wrong encrypted aggregate input root, share ciphertext root, reconstruction hash, and bridge witness privacy profile hash must reject.',
        id: 'encrypted-aggregate-root-binding',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: [
            'matrix-cheap',
            'matrix-sentinel',
            'protocol-structure',
            'rust-wasm-verifier',
        ],
        status: 'covered',
    },
    {
        description:
            'Public aggregate opening, public bridge witness, public aggregate witness, BGV plaintext witness, encryption randomness, error/noise, and t_pvss aggregate witnesses must reject as witness disclosure.',
        id: 'forbidden-witness-disclosure',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: [
            'matrix-cheap',
            'matrix-sentinel',
            'protocol-structure',
        ],
        status: 'covered',
    },
    {
        description:
            'Public aggregate histograms, exact scores, score bits, plaintext score-bit inputs, and plaintext comparison inputs must reject.',
        id: 'forbidden-aggregate-plaintext-disclosure',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['protocol-structure', 'matrix-cheap'],
        status: 'covered',
    },
    {
        description:
            'Sampled-only, pending, shell-only, or forged bridge records must not become selected contributions.',
        id: 'sampled-or-forged-bridge-record',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: [
            'matrix-cheap',
            'matrix-sentinel',
            'protocol-structure',
            'rust-wasm-verifier',
        ],
        status: 'covered',
    },
    {
        description:
            'Wrong BGV public key root, collective public key root, BGV profile, backend profile, RNS limb relation, CRT consistency, coefficient-domain canonicalization, or mixed NTT/coefficient-domain object must reject.',
        id: 'bgv-key-and-domain-binding',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: [
            'matrix-cheap',
            'matrix-sentinel',
            'rust-wasm-verifier',
        ],
        status: 'covered',
    },
    {
        description:
            'Mutated shared-witness commitments, Fiat-Shamir challenges, transcript labels, proof/status Hashes, status evidence, and out-of-bound response vectors must reject.',
        id: 'shared-witness-proof-binding',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['matrix-sentinel', 'rust-wasm-verifier'],
        status: 'covered',
    },
    {
        description:
            'Mutated BGV randomness-bound commitments, support-polynomial commitments, status evidence, status Hashes, and unsupported boundedness proof-byte decorations must reject.',
        id: 'bgv-boundedness-status-binding',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['matrix-sentinel', 'rust-wasm-verifier'],
        status: 'covered',
    },
    {
        description:
            'Wrong contributor roster acceptance hash, stale recovery epoch, cloned device epoch, wrong manifest, roster, board head, selection policy, or post-voting-closed context must reject.',
        id: 'context-and-epoch-binding',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['matrix-cheap', 'protocol-structure'],
        status: 'covered',
    },
    {
        description:
            'Published interpolation coefficients, coefficient L1 sums, and encrypted aggregate reconstruction roots must be recomputed and bound into aggregate-ready verification.',
        id: 'aggregate-ready-recomputation',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['protocol-structure', 'matrix-cheap'],
        status: 'covered',
    },
    {
        description:
            'The public SDK bridge verifier must reject malformed proofs, unrelated contexts, wrong hash roots, sampled-only evidence, and unpinned package-kernel behavior without exposing generation or witness material.',
        id: 'public-sdk-misuse-coverage',
        designNoteSource: 'internal bridge negative-coverage section',
        requiredSurfaces: ['sdk-verifier'],
        status: 'covered',
    },
];

export const negativeInventoryMarkdown = (
    items: readonly NegativeInventoryItem[] = negativeInventory,
): string => {
    const lines = [
        '# Encrypted aggregate bridge negative-suite inventory',
        '',
        '| id | description | required surfaces | status |',
        '| - | - | - | - |',
        ...items.map((item) =>
            [
                item.id,
                item.description,
                item.requiredSurfaces.join(', '),
                item.status,
            ].join(' | '),
        ),
    ];

    return `${lines.join('\n')}\n`;
};
