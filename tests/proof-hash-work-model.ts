import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotEncryptionRelationCensus } from '#tests/ballot-encryption-relation-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileBallotWordProofLayout,
    compileFullWordProofLayout,
    compileLinkedReleaseWordProofLayout,
    compileRegistrationWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { compileLinkedReleaseColumnLayout } from '#tests/linked-release-relation-model.js';
import { participantReleaseProofRoleBytes } from '#tests/participant-release-custody-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import {
    compileWideChallengeCompilerCensus,
    proofCompilerCaps,
} from '#tests/wide-challenge-compiler-model.js';

export const byteAlignedSpongePermutations = (
    inputBytes: bigint,
    outputBytes: bigint,
    rateBytes: bigint,
) => {
    if (
        inputBytes < 0n ||
        outputBytes < 0n ||
        ![72n, 136n, 168n].includes(rateBytes)
    )
        throw new RangeError('Invalid SHA3 or SHAKE byte count.');
    // FIPS 202 Algorithm 8 and its byte-aligned SHA-3/SHAKE suffixes.
    const absorption = inputBytes / rateBytes + 1n;
    const outputBlocks = (outputBytes + rateBytes - 1n) / rateBytes;
    return absorption + (outputBlocks > 0n ? outputBlocks - 1n : 0n);
};

export const framedProofHashBytes = (
    domain: string,
    parts: readonly bigint[],
) => {
    const domainBytes = BigInt(Buffer.byteLength(domain));
    if (
        [domainBytes, ...parts].some(
            (value) => value < 0n || value > 0xffffffffn,
        )
    )
        throw new RangeError('A proof-hash part exceeds its u32 framing.');
    return (
        4n + domainBytes + parts.reduce((sum, value) => sum + 4n + value, 0n)
    );
};

// The protocol digest's fixed ASCII domain, zero-padded to this width,
// precedes the existing proof framing. It adds no salt entropy.
const protocolHashPrefixBytes = 64n;
const fixedHashInputBytes = (domain: string, parts: readonly bigint[]) =>
    protocolHashPrefixBytes + framedProofHashBytes(domain, parts);

// Every salted proof-hash input shape of one role: a leaf of each opened
// group, in verifier order, and the three message-root shapes.
export const saltedProofHashInputs = (
    role: Readonly<{ firstWidth: bigint; secondWidth: bigint }>,
    roleBytes: bigint,
) => {
    const query = compileProofVerifierQueryCensus();
    const extension =
        compileSmallLimbProofFieldCensus().packedExtensionElementByteLength;
    const tag = proofCompilerCaps.tagBits / 8n,
        salt = proofCompilerCaps.saltBits / 8n;
    const widths = query.groups.map((_group, index) =>
        index === 0
            ? role.firstWidth
            : index === 1
              ? role.secondWidth
              : extension,
    );
    return {
        saltBytes: salt,
        widths,
        leaves: widths.map((width) =>
            fixedHashInputBytes('bounded-proof/leaf', [
                roleBytes,
                4n,
                4n,
                salt,
                width,
            ]),
        ),
        messageRoots: [
            fixedHashInputBytes('bounded-proof/message-root', [
                roleBytes,
                tag,
                4n,
                salt,
                tag,
            ]),
            fixedHashInputBytes('bounded-proof/message-root', [
                roleBytes,
                tag,
                4n,
                salt,
                tag,
                extension,
            ]),
            fixedHashInputBytes('bounded-proof/message-root', [
                roleBytes,
                tag,
                4n,
                salt,
                extension,
            ]),
        ],
    };
};

type Work = {
    queries: bigint;
    inputBytes: bigint;
    outputBytes: bigint;
    permutations: bigint;
};
const work = (
    queries: bigint,
    input: bigint,
    output: bigint,
    rate: bigint,
): Work => ({
    queries,
    inputBytes: queries * input,
    outputBytes: queries * output,
    permutations: queries * byteAlignedSpongePermutations(input, output, rate),
});
const total = (values: readonly Work[]): Work =>
    values.reduce(
        (sum, value) => ({
            queries: sum.queries + value.queries,
            inputBytes: sum.inputBytes + value.inputBytes,
            outputBytes: sum.outputBytes + value.outputBytes,
            permutations: sum.permutations + value.permutations,
        }),
        { queries: 0n, inputBytes: 0n, outputBytes: 0n, permutations: 0n },
    );

export const proofHashProfiles = (profile: SupportedProfile) => {
    const registration = compileRegistrationKeyRelationCensus();
    const setup = compileSetupContributionRelationCensus(profile);
    const ballot = compileBallotEncryptionRelationCensus(profile);
    const ballotBody = compileBallotBodyCensus(profile);
    const release = compileLinkedReleaseColumnLayout(profile);
    const byteWidth = (value: bigint) =>
        BigInt(Math.ceil(value.toString(2).length / 8));
    const shareBytes = byteWidth(registration.modulus);
    const releaseBytes = byteWidth(profile.release.modulus);
    const rows = [
        {
            role: 'registration',
            layout: compileRegistrationWordProofLayout(),
            columns: registration.wordColumns + registration.booleanColumns,
            booleans: registration.booleanColumns,
            lookups: registration.lookups,
            products: registration.disjointPairs,
            prefixWords: 15n,
            statementBytes: registration.statementBytes,
            relationTag: 'recipient-registration-key/1',
            roleBytes: compileRegistrationEnrollmentCensus().proofRoleBytes,
        },
        {
            role: 'setup',
            layout: compileFullWordProofLayout(profile),
            columns: setup.wordColumns + setup.booleanColumns,
            booleans: setup.booleanColumns,
            lookups: setup.lookupEntries,
            products: setup.disjointPairs,
            prefixWords: 18n,
            statementBytes: setup.expandedStatementByteLength,
            relationTag: 'complete-setup-words/2',
            roleBytes: compileRosterProposalCensus(profile.participantCount)
                .roleBytes,
        },
        {
            role: 'ballot',
            layout: compileBallotWordProofLayout(profile),
            columns: ballot.wordColumns + ballot.booleanColumns,
            booleans: ballot.booleanColumns,
            lookups: ballot.lookupEntries,
            products: ballot.additionalQuadraticConstraints,
            prefixWords: 20n,
            statementBytes:
                ballotBody.contextBytes + 2n * ballotBody.ciphertextBytes,
            relationTag: 'linked-scored-ballot/1',
            roleBytes: ballotBody.proofRoleBytes,
        },
        {
            role: 'release',
            layout: compileLinkedReleaseWordProofLayout(profile),
            columns: release.wordColumns + release.booleanColumns,
            booleans: release.booleanColumns,
            lookups: release.lookups.length,
            products: 1,
            prefixWords:
                15n +
                BigInt(release.columns.length) +
                3n +
                shareBytes / 4n +
                releaseBytes / 4n,
            statementBytes:
                4n +
                3n * 64n +
                2n +
                fixedModulusBfvInputs.polynomialDegree *
                    (4n * (shareBytes + 1n) + 2n * (releaseBytes + 1n)),
            relationTag: 'linked-threshold-release/1',
            roleBytes: participantReleaseProofRoleBytes,
        },
    ];
    return rows.map((row) => {
        const oracles =
            row.columns + 2 * row.lookups + row.booleans + row.products + 6;
        return {
            role: row.role,
            firstWidth: row.layout.firstWidth,
            secondWidth: row.layout.secondWidth,
            parameterBytes:
                4n * (row.prefixWords + BigInt(oracles)) +
                8n * BigInt(row.lookups),
            statementBytes: row.statementBytes,
            relationTag: row.relationTag,
            roleBytes: row.roleBytes,
        };
    });
};

export const compileProofHashWork = (
    supportedProfile: SupportedProfile,
    profile: ReturnType<typeof proofHashProfiles>[number],
    roleBytes = profile.roleBytes,
) => {
    if (roleBytes < 1n || roleBytes > 1024n)
        throw new RangeError('Unsupported verifier role length.');
    const query = compileProofVerifierQueryCensus();
    const compiler = compileWideChallengeCompilerCensus(supportedProfile);
    const tag = compiler.tagBits / 8n;
    const message = BigInt(compiler.challengeBytes);
    const nodeInput = fixedHashInputBytes('bounded-proof/node', [
        roleBytes,
        4n,
        4n,
        tag,
        tag,
    ]);
    const salted = saltedProofHashInputs(profile, roleBytes);
    const groups = query.groups.map((group, index) => {
        const width = salted.widths[index];
        const leafInput = salted.leaves[index];
        const leafPrefixPermutations =
            fixedHashInputBytes('bounded-proof/leaf', [roleBytes, 4n]) / 136n;
        const nodePrefixPermutations =
            fixedHashInputBytes('bounded-proof/node', [roleBytes, 4n, 4n]) /
            136n;
        // The verifier keeps one leaf and one node prefix per group, whose
        // node prefix ends before the level.
        const verifierNodePrefixPermutations =
            fixedHashInputBytes('bounded-proof/node', [roleBytes, 4n]) / 136n;
        const levels = BigInt(Math.log2(group.length));
        const savedPermutations =
            BigInt(group.length - 1) * leafPrefixPermutations +
            (BigInt(group.length - 1) - levels) * nodePrefixPermutations;
        const proverWithoutPrefixReuse = total([
            work(BigInt(group.length), leafInput, tag, 136n),
            work(BigInt(group.length - 1), nodeInput, tag, 136n),
        ]);
        const verifierWithoutPrefixReuse = total([
            work(BigInt(group.maximumLeafQueries), leafInput, tag, 136n),
            work(BigInt(group.maximumNodeQueries), nodeInput, tag, 136n),
        ]);
        return {
            length: group.length,
            width,
            prover: {
                ...proverWithoutPrefixReuse,
                permutations:
                    proverWithoutPrefixReuse.permutations - savedPermutations,
            },
            proverWithoutPrefixReuse,
            prefixReuse: {
                savedPermutations,
                stateClones: 2n * BigInt(group.length) - 1n,
                initializations: 1n + levels,
            },
            verifier: {
                ...verifierWithoutPrefixReuse,
                permutations:
                    verifierWithoutPrefixReuse.permutations -
                    BigInt(group.maximumLeafQueries - 1) *
                        leafPrefixPermutations -
                    BigInt(group.maximumNodeQueries - 1) *
                        verifierNodePrefixPermutations,
            },
            verifierWithoutPrefixReuse,
        };
    });
    const contextInput = fixedHashInputBytes('bounded-proof/statement', [
        roleBytes,
        BigInt(Buffer.byteLength(profile.relationTag)),
        16n,
        16n,
        16n,
        profile.parameterBytes,
        16n,
        profile.statementBytes,
    ]);
    const transcript = total([
        work(
            BigInt(query.verifierMessageQueries),
            framedProofHashBytes('bounded-proof/verifier-message', [
                roleBytes,
                tag,
                message,
                4n,
            ]),
            message,
            136n,
        ),
        work(
            BigInt(query.chainStateQueries),
            framedProofHashBytes('bounded-proof/chain-state', [
                roleBytes,
                tag,
                message,
                tag,
            ]),
            message,
            136n,
        ),
        work(
            BigInt(query.messageRootQueries - 2),
            salted.messageRoots[0],
            tag,
            136n,
        ),
        work(1n, salted.messageRoots[1], tag, 136n),
        work(1n, salted.messageRoots[2], tag, 136n),
        work(1n, contextInput, tag, 136n),
    ]);
    return {
        role: profile.role,
        roleBytes,
        groups,
        transcript,
        proverCore: total([transcript, ...groups.map((group) => group.prover)]),
        proverCoreWithoutPrefixReuse: total([
            transcript,
            ...groups.map((group) => group.proverWithoutPrefixReuse),
        ]),
        verifierCore: total([
            transcript,
            ...groups.map((group) => group.verifier),
        ]),
        verifierCoreWithoutPrefixReuse: total([
            transcript,
            ...groups.map((group) => group.verifierWithoutPrefixReuse),
        ]),
        // A separate operand for callers' plain statement-identity passes.
        // Multiplicity, common-matrix generation and outer envelopes are not
        // hidden in the proof-core totals.
        statementDigestPass: work(
            1n,
            protocolHashPrefixBytes + profile.statementBytes,
            tag,
            136n,
        ),
    };
};
