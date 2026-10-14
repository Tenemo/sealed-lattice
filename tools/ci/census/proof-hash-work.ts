import {
    compileProofHashWork,
    proofHashProfiles,
    setupFirstOracleResumeWork,
} from '#tests/proof-hash-work-model.js';
import { firstOracleResumeFactor } from '#tests/security-margin/reduction-work.js';
import {
    completionProfile,
    deriveSupportedProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';

// The largest complete-input factor of a resumed setup first-oracle leaf over
// every supported profile.
export const maximumFirstOracleResumeFactor = () =>
    listSupportedProfiles()
        .map(firstOracleResumeFactor)
        .reduce((maximum, factor) => (factor > maximum ? factor : maximum), 0n);

export const renderProofHashByteAndPermutationWork = (): string[] => {
    const completion = completionProfile();
    const maximumFirstOracleResume = maximumFirstOracleResumeFactor();
    return [
        '## Proof hash byte and permutation work',
        '',
        'The first table counts initial commitment-tree leaf/node hashing, the Fiat-Shamir transcript and context once, or one canonical verifier pass. Prover prefixes are initialized per row/subtree job and per level above those subtrees. Logical hash inputs and outputs are unchanged by prefix reuse; the permutation columns retain the actual initialization multiplicity. The second table adds bounded opening-block reconstruction and leaf-salt expansion. Operation/mask randomness streams, clone/allocation work, statement-digest passes, fixed-matrix generation, wrappers, checkpoint/replay work and lifetime multiplicities remain separate. The Merkle expansion factor bounds a complete-input hash against its remaining uncached permutations, not the full reduction. These are FIPS reference-permutation counts, not native timings, quantum gate bounds or a full participant total. The release row uses the authenticated protocol role specified by the foundation owner.',
        '',
        table(
            [
                'Role',
                'Role bytes',
                'Verifier message bytes',
                'Prover core logical input bytes',
                'Prover permutations without prefix reuse',
                'Prover permutations with prefix reuse',
                'Prover prefix initializations',
                'Merkle complete-input factor',
                'Verifier core hash input bytes',
                'Verifier permutations without prefix reuse',
                'Verifier permutations with prefix reuse',
                'One statement-digest pass permutations',
            ],
            proofHashProfiles(completion).map((profile) => {
                const value = compileProofHashWork(completion, profile);
                return [
                    profile.role,
                    formatCount(value.roleBytes),
                    formatCount(profile.messageBytes),
                    formatCount(value.proverCore.inputBytes),
                    formatCount(
                        value.proverCoreWithoutPrefixReuse.permutations,
                    ),
                    formatCount(value.proverCore.permutations),
                    formatCount(
                        value.groups.reduce(
                            (sum, group) =>
                                sum + group.prefixReuse.initializations,
                            0n,
                        ),
                    ),
                    formatCount(
                        value.groups.reduce(
                            (maximum, group) =>
                                group.prefixReuse.completeInputFactor > maximum
                                    ? group.prefixReuse.completeInputFactor
                                    : maximum,
                            0n,
                        ),
                    ),
                    formatCount(value.verifierCore.inputBytes),
                    formatCount(
                        value.verifierCoreWithoutPrefixReuse.permutations,
                    ),
                    formatCount(value.verifierCore.permutations),
                    formatCount(value.statementDigestPass.permutations),
                ];
            }),
        ),
        '',
        'The first two trees retain leaf digests. The linear and folding trees restore the complete aligned blocks containing queried leaves, then rebuild the lower internal-node cache used by path writing. Each emitted record also expands its original leaf salt again. Counts below bound one complete producer pass at the independently bounded query counts; repeated calls are work, not new salt-seed scopes. Correlations between stages can make the sum conservative.',
        '',
        table(
            [
                'Role',
                'Opening leaf hashes bound',
                'Opening node hashes bound',
                'Leaf-salt expansions bound',
                'Opening fixed-hash permutations bound',
                'Tree/transcript/salt permutations subtotal',
            ],
            proofHashProfiles(completion).map((profile) => {
                const value = compileProofHashWork(completion, profile);
                return [
                    profile.role,
                    formatCount(
                        value.groups.reduce(
                            (sum, group) =>
                                sum +
                                BigInt(group.openingCounts.restoredLeaves),
                            0n,
                        ),
                    ),
                    formatCount(
                        value.groups.reduce(
                            (sum, group) =>
                                sum + BigInt(group.openingCounts.nodeHashes),
                            0n,
                        ),
                    ),
                    formatCount(value.proverLeafSaltExpansion.queries),
                    formatCount(value.proverOpeningHashes.permutations),
                    formatCount(value.proverHashSubtotal.permutations),
                ];
            }),
        ),
        '',
        'A first-oracle checkpoint may retain all base columns while leaving the extension degree-mask column unhashed. The following rows use that latest cut, which maximizes the complete-input/resumed-permutation ratio for each fixed role and profile. The bound applies separately to every completed replay without recharging historical absorption. Original input availability, its reconstruction and storage, authentication, incomplete calls and private-state coupling remain separate. Use the larger of this factor and the covered reader/Merkle factor in a mixed oracle schedule; do not multiply those alternative conversions.',
        '',
        table(
            [
                'Participants / options',
                'First leaf bytes including framing',
                'Retained prefix bytes per leaf',
                'Remaining input bytes per leaf',
                'Complete-input permutations per leaf',
                'Resumed permutations per leaf',
                'Complete-input factor',
            ],
            [
                [3, 2],
                [10, 10],
                [20, 20],
            ].map(([participants, options]) => {
                const work = setupFirstOracleResumeWork(
                    deriveSupportedProfile(participants, options),
                );
                return [
                    `${participants} / ${options}`,
                    ...[
                        work.completeInputBytes,
                        work.retainedPrefixBytes,
                        work.remainingInputBytes,
                        work.completeInputPermutations,
                        work.resumedPermutations,
                        work.completeInputFactor,
                    ].map(formatCount),
                ];
            }),
        ),
        '',
        table(
            ['Scope', 'Complete-input factor'],
            [
                [
                    'Maximum over every supported profile with its emitted setup role',
                    formatCount(maximumFirstOracleResume),
                ],
            ],
        ),
        '',
    ];
};
