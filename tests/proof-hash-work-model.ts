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
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

export const byteAlignedSpongePermutations = (
    inputBytes: bigint,
    outputBytes: bigint,
    rateBytes: bigint,
) => {
    if (inputBytes < 0n || outputBytes < 0n || ![72n, 136n].includes(rateBytes))
        throw new RangeError('Invalid SHA3-512 or SHAKE256 byte count.');
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

export const proofHashProfiles = () => {
    const registration = compileRegistrationKeyRelationCensus();
    const setup = compileSetupContributionRelationCensus();
    const ballot = compileBallotEncryptionRelationCensus();
    const ballotBody = compileBallotBodyCensus();
    const release = compileLinkedReleaseColumnLayout();
    const byteWidth = (value: bigint) =>
        BigInt(Math.ceil(value.toString(2).length / 8));
    const shareBytes = byteWidth(registration.modulus);
    const releaseBytes = byteWidth(fixedModulusBfvInputs.releaseModulus);
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
            layout: compileFullWordProofLayout(),
            columns: setup.wordColumns + setup.booleanColumns,
            booleans: setup.booleanColumns,
            lookups: setup.lookupEntries,
            products: setup.disjointPairs,
            prefixWords: 19n,
            statementBytes: setup.expandedStatementByteLength,
            relationTag: 'complete-setup-words/1',
            roleBytes: compileRosterProposalCensus(
                Number(fixedModulusBfvInputs.participantCount),
            ).roleBytes,
        },
        {
            role: 'ballot',
            layout: compileBallotWordProofLayout(),
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
        // The complete authenticated release role is not implemented. This row
        // uses the actual numerical workload role, not a production substitute.
        {
            role: 'release',
            layout: compileLinkedReleaseWordProofLayout(),
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
            roleBytes: BigInt(
                Buffer.byteLength('sealed-lattice/linked-release-workload/1'),
            ),
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
    profile: ReturnType<typeof proofHashProfiles>[number],
    roleBytes = profile.roleBytes,
) => {
    if (roleBytes < 1n || roleBytes > 1024n)
        throw new RangeError('Unsupported verifier role length.');
    const query = compileProofVerifierQueryCensus();
    const field = compileSmallLimbProofFieldCensus();
    const compiler = compileWideChallengeCompilerCensus();
    const tag = compiler.tagBits / 8n,
        salt = compiler.saltBits / 8n;
    const message = BigInt(compiler.challengeBytes);
    const nodeInput = framedProofHashBytes('bounded-proof/node', [
        roleBytes,
        4n,
        4n,
        tag,
        tag,
    ]);
    const groups = query.groups.map((group, index) => {
        const width =
            index === 0
                ? profile.firstWidth
                : index === 1
                  ? profile.secondWidth
                  : field.packedExtensionElementByteLength;
        const leafInput = framedProofHashBytes('bounded-proof/leaf', [
            roleBytes,
            4n,
            4n,
            salt,
            width,
        ]);
        return {
            length: group.length,
            width,
            prover: total([
                work(BigInt(group.length), leafInput, tag, 72n),
                work(BigInt(group.length - 1), nodeInput, tag, 72n),
            ]),
            verifier: total([
                work(BigInt(group.maximumLeafQueries), leafInput, tag, 72n),
                work(BigInt(group.maximumNodeQueries), nodeInput, tag, 72n),
            ]),
        };
    });
    const contextInput = framedProofHashBytes('bounded-proof/statement', [
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
            framedProofHashBytes('bounded-proof/message-root', [
                roleBytes,
                tag,
                4n,
                salt,
                tag,
            ]),
            tag,
            72n,
        ),
        work(
            1n,
            framedProofHashBytes('bounded-proof/message-root', [
                roleBytes,
                tag,
                4n,
                salt,
                tag,
                field.packedExtensionElementByteLength,
            ]),
            tag,
            72n,
        ),
        work(
            1n,
            framedProofHashBytes('bounded-proof/message-root', [
                roleBytes,
                tag,
                4n,
                salt,
                field.packedExtensionElementByteLength,
            ]),
            tag,
            72n,
        ),
        work(1n, contextInput, tag, 72n),
    ]);
    return {
        role: profile.role,
        roleBytes,
        groups,
        transcript,
        proverCore: total([transcript, ...groups.map((group) => group.prover)]),
        verifierCore: total([
            transcript,
            ...groups.map((group) => group.verifier),
        ]),
        // A separate operand for callers' plain statement-identity passes.
        // Multiplicity, common-matrix generation and outer envelopes are not
        // hidden in the proof-core totals.
        statementDigestPass: work(1n, profile.statementBytes, tag, 72n),
    };
};
