import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { protocolHashPrefix } from '#tests/word-proof-reference/transcript.js';

const aggregateRole = Buffer.from('sealed-lattice/setup-aggregate');
const headerBytes = (profile: SupportedProfile) =>
    4 + Math.ceil(profile.ciphertext.modulus.toString(2).length / 8);
const fixedBytes = (domain: string, fields: readonly bigint[]) =>
    64n +
    4n +
    BigInt(domain.length) +
    fields.reduce((sum, bytes) => sum + 4n + bytes, 0n);

export const compilePublicEvaluationHashCensus = (
    profile: SupportedProfile,
) => {
    const offer = compileCommittedOfferCensus(profile);
    const roleBytes = BigInt(aggregateRole.length + 64);
    const transcriptInputs = [
        26n +
            BigInt('sealed-lattice/setup-limb-sum'.length) +
            offer.maximumAggregateBytes /
                BigInt(offer.committedPolynomials.length),
        26n +
            BigInt('sealed-lattice/published-aggregate'.length) +
            64n +
            offer.aggregateManifestBytes,
        fixedBytes('committed-key/evaluation-statement', [
            roleBytes,
            BigInt(headerBytes(profile)),
            28n,
            64n * BigInt(profile.setupContributorCount),
        ]),
        ...[[64n], [4n, 48n], [48n]].map((parts) =>
            fixedBytes('bounded-proof/message-root', [
                roleBytes,
                64n,
                4n,
                128n,
                ...parts,
            ]),
        ),
        fixedBytes('bounded-proof/verifier-message', [
            roleBytes,
            64n,
            offer.evaluationMessageBytes,
            4n,
        ]) - 64n,
        fixedBytes('bounded-proof/chain-state', [
            roleBytes,
            64n,
            offer.evaluationMessageBytes,
            64n,
        ]) - 64n,
    ];
    const groups = Array.from({ length: offer.evaluationFolds }, (_, stage) => {
        const leaves = 262144n >> BigInt(stage);
        const openedLeaves =
            leaves < 2n * BigInt(offer.evaluationQueries)
                ? leaves
                : 2n * BigInt(offer.evaluationQueries);
        let parentHashes = 0n;
        for (let length = leaves / 2n; length > 0n; length /= 2n)
            parentHashes += length < openedLeaves ? length : openedLeaves;
        return {
            leaves,
            openedLeaves,
            parentHashes,
            width: stage === 0 ? 16n * offer.committedColumns : 48n,
        };
    });
    return {
        roleBytes,
        messageBytes: offer.evaluationMessageBytes,
        transcriptQueries: 3n * BigInt(offer.evaluationFolds) + 8n,
        maximumInputBits:
            8n *
            transcriptInputs.reduce(
                (maximum, value) => (value > maximum ? value : maximum),
                0n,
            ),
        groups,
        maximumVerifierQueries:
            3n * BigInt(offer.evaluationFolds) +
            8n +
            groups.reduce(
                (sum, group) => sum + group.openedLeaves + group.parentHashes,
                0n,
            ),
        // Each job re-encodes the public root once; each opening is rehashed
        // before output. Fold layers are generated once and kept for output.
        proverTreeQueries: groups.reduce(
            (sum, group) => sum + 2n * group.leaves - 1n + group.openedLeaves,
            0n,
        ),
    };
};

// This family is public and deterministic. It has no original-owner exemption
// and no programmable message in the honest proof simulator.
export const parsePublicEvaluationHashInput = (input: Uint8Array) => {
    const bytes = Buffer.from(input);
    // Foundation identity hashes use a canonical tuple, outside the proof's
    // framed prefix. These public preimages fix the sum before its challenge.
    if (
        bytes.length >= 26 &&
        bytes.readUInt16LE(0) === 1 &&
        bytes.readUInt32LE(2) === 2 &&
        bytes.readUInt16LE(6) === 2
    ) {
        const labelLength = bytes.readUInt32LE(12);
        const payloadOffset = 16 + labelLength;
        if (
            bytes.readUInt32LE(8) === 4 + labelLength &&
            payloadOffset + 10 <= bytes.length &&
            bytes.readUInt16LE(payloadOffset) === 1 &&
            bytes.readUInt32LE(payloadOffset + 2) ===
                bytes.length - payloadOffset - 6 &&
            bytes.readUInt32LE(payloadOffset + 6) ===
                bytes.length - payloadOffset - 10
        ) {
            const label = bytes.subarray(16, payloadOffset);
            const payload = bytes.subarray(payloadOffset + 10);
            if (
                label.equals(
                    Buffer.from('sealed-lattice/published-aggregate'),
                ) &&
                listSupportedProfiles().some(
                    (profile) =>
                        BigInt(payload.length) ===
                        64n +
                            compileCommittedOfferCensus(profile)
                                .aggregateManifestBytes,
                )
            )
                return {
                    family: 'aggregate-identity',
                    role: Buffer.alloc(0),
                    fields: [payload],
                };
            if (
                label.equals(Buffer.from('sealed-lattice/setup-limb-sum')) &&
                listSupportedProfiles().some((profile) => {
                    const limbs = Math.ceil(profile.ciphertext.bits / 96);
                    const value = compileCommittedOfferCensus(profile);
                    return (
                        payload.length % (65536 * limbs) === 0 &&
                        BigInt(payload.length / (65536 * limbs)) >=
                            value.generatedAggregateLimbBytes &&
                        BigInt(payload.length / (65536 * limbs)) <=
                            value.maximumAggregateLimbBytes
                    );
                })
            )
                return {
                    family: 'limb-sum',
                    role: Buffer.alloc(0),
                    fields: [payload],
                };
        }
    }
    const fixed = bytes
        .subarray(0, protocolHashPrefix.length)
        .equals(protocolHashPrefix);
    let offset = fixed ? protocolHashPrefix.length : 0;
    const fields: Buffer[] = [];
    while (offset < bytes.length) {
        if (bytes.length - offset < 4) return undefined;
        const length = bytes.readUInt32LE(offset);
        offset += 4;
        if (length > bytes.length - offset) return undefined;
        fields.push(bytes.subarray(offset, offset + length));
        offset += length;
    }
    const [domain, role, ...parts] = fields;
    if (
        !domain ||
        !role ||
        !role.subarray(0, aggregateRole.length).equals(aggregateRole)
    )
        return undefined;
    const mainRole = role.length === aggregateRole.length + 64;
    const treeRole = role.length === aggregateRole.length + 72;
    const shape = (...lengths: number[]) =>
        lengths.length === parts.length &&
        parts.every((part, index) => part.length === lengths[index]);
    const named = (name: string) => domain.equals(Buffer.from(name));
    const profiles = listSupportedProfiles();
    let family: string | undefined;
    if (fixed && treeRole && named('committed-key/leaf') && shape(4, 48))
        family = 'leaf';
    if (fixed && treeRole && named('committed-key/node') && shape(4, 64, 64))
        family = 'node';
    if (
        fixed &&
        mainRole &&
        named('committed-key/evaluation-statement') &&
        profiles.some((profile) =>
            shape(headerBytes(profile), 28, 64 * profile.setupContributorCount),
        )
    )
        family = 'statement';
    if (
        fixed &&
        mainRole &&
        named('bounded-proof/message-root') &&
        (shape(64, 4, 128, 64) ||
            shape(64, 4, 128, 4, 48) ||
            shape(64, 4, 128, 48))
    )
        family = 'message-root';
    if (
        !fixed &&
        mainRole &&
        named('bounded-proof/verifier-message') &&
        profiles.some((profile) =>
            shape(
                64,
                Number(
                    compileCommittedOfferCensus(profile).evaluationMessageBytes,
                ),
                4,
            ),
        )
    )
        family = 'verifier-message';
    if (
        !fixed &&
        mainRole &&
        named('bounded-proof/chain-state') &&
        profiles.some((profile) =>
            shape(
                64,
                Number(
                    compileCommittedOfferCensus(profile).evaluationMessageBytes,
                ),
                64,
            ),
        )
    )
        family = 'chain-state';
    return family === undefined ? undefined : { family, role, fields: parts };
};
