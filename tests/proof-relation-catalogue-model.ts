import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileBallotEncryptionColumnLayout } from '#tests/ballot-encryption-relation-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseColumnLayout } from '#tests/linked-release-relation-model.js';
import { proofHashProfiles } from '#tests/proof-hash-work-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

// Only the four immutable supported-profile constructors belong to this
// catalogue. Arbitrary mutable Rust Relation values do not: their serialized
// parameters omit generic product pairs and narrow a u128 lookup scale to u32.
const agreement = compileCommonAgreementDegreeCensus();
const field = compileSmallLimbProofFieldCensus();
const degree = Number(fixedModulusBfvInputs.polynomialDegree);
const sharing = shareEncryptionParameters;
const auxiliary = auxiliaryInputEncryptionParameters;
export const proofCatalogueInteger = (value: bigint, width: number): Buffer => {
    if (value < 0n || value >= 1n << BigInt(8 * width))
        throw new RangeError('Integer does not fit its catalogue encoding.');
    const bytes = Buffer.alloc(width);
    for (let index = 0; index < width; index++, value >>= 8n)
        bytes[index] = Number(value & 255n);
    return bytes;
};
const words = (values: readonly (number | bigint)[]) =>
    Buffer.concat(
        values.map((value) => proofCatalogueInteger(BigInt(value), 4)),
    );
const width = (value: bigint) => Math.ceil(value.toString(2).length / 8);
type PolynomialFamily = { count: number; degree: number; modulus: bigint };

export const proofRelationCatalogueEntry = (profile: SupportedProfile) =>
    proofHashProfiles(profile).map((hash) => {
        let wordColumns: number;
        let booleanColumns: number;
        let products: number;
        let lookups: { column: number; factor: bigint }[];
        let parameters: (number | bigint)[];
        let families: PolynomialFamily[];
        let header: Buffer;
        let arithmeticKey: string;
        switch (hash.role) {
            case 'registration':
                wordColumns = 3;
                booleanColumns = 2;
                products = 1;
                lookups = [0, 1, 2].map((column) => ({ column, factor: 1n }));
                lookups.push({ column: 2, factor: 512n });
                parameters = [degree, 3, 2, 4, 256, 96, 16, 7];
                header = Buffer.concat([
                    Buffer.from('RKS1'),
                    words([degree]),
                    proofCatalogueInteger(sharing.modulus, 20),
                ]);
                families = [{ count: 2, degree, modulus: sharing.modulus }];
                arithmeticKey = 'registration';
                break;
            case 'setup': {
                const lifting = profile.shareLifting;
                const limbs = Math.ceil(profile.ciphertext.bits / 96);
                // Allocation order is source-significant for lookup columns:
                // sharing coefficients precede gadget equations.
                const variables = [
                    ...Array.from(
                        { length: profile.releaseThreshold - 1 },
                        () => [
                            lifting.limbBits,
                            lifting.sharingCoefficientBits - lifting.limbBits,
                        ],
                    ).flat(),
                    ...Array.from(
                        { length: 4 * Number(profile.gadgetLength) },
                        () => [
                            16,
                            ...Array.from({ length: limbs - 1 }, () => 16),
                            7,
                        ],
                    ).flat(),
                    ...Array.from({ length: profile.participantCount }, () => [
                        16,
                        lifting.carryBits,
                        7,
                        16,
                        16,
                        7,
                    ]).flat(),
                ];
                wordColumns = 0;
                products = profile.participantCount + 2;
                booleanColumns = 2 * products;
                const narrow: { column: number; factor: bigint }[] = [];
                for (const bits of variables) {
                    if (bits < 16) {
                        narrow.push({
                            column: wordColumns++,
                            factor: 1n << BigInt(16 - bits),
                        });
                    } else {
                        wordColumns += Math.floor(bits / 16);
                        booleanColumns += bits % 16;
                    }
                }
                lookups = [
                    ...Array.from({ length: wordColumns }, (_, column) => ({
                        column,
                        factor: 1n,
                    })),
                    ...narrow,
                ];
                parameters = [
                    degree,
                    wordColumns,
                    booleanColumns,
                    lookups.length,
                    fixedModulusBfvInputs.secretSupportWeight,
                    sharing.encryptionSupportWeight,
                    lifting.sharingCoefficientBits,
                    lifting.limbBits,
                    16,
                    7,
                    lifting.carryBits,
                ];
                header = Buffer.concat([
                    Buffer.from('SCO2'),
                    words([degree]),
                    proofCatalogueInteger(
                        profile.ciphertext.modulus,
                        width(profile.ciphertext.modulus),
                    ),
                    proofCatalogueInteger(sharing.modulus, 20),
                ]);
                families = [
                    {
                        count: 7 * Number(profile.gadgetLength),
                        degree,
                        modulus: profile.ciphertext.modulus,
                    },
                    {
                        count: 3 * profile.participantCount + 1,
                        degree,
                        modulus: sharing.modulus,
                    },
                ];
                arithmeticKey = `setup:${profile.participantCount}:${profile.ciphertext.modulus}`;
                break;
            }
            case 'ballot': {
                const layout = compileBallotEncryptionColumnLayout(profile);
                wordColumns = layout.wordColumns;
                booleanColumns = 5;
                products = layout.zeroProducts.length;
                lookups = layout.lookups.map(({ column, scale }) => ({
                    column,
                    factor: BigInt(scale),
                }));
                parameters = [
                    wordColumns,
                    booleanColumns,
                    lookups.length,
                    fixedModulusBfvInputs.secretSupportWeight,
                    auxiliary.support,
                    32768,
                    65536,
                    ...layout.zeroProducts.flat(),
                ];
                header = Buffer.from('LBS1');
                families = [
                    { count: 4, degree, modulus: profile.ciphertext.modulus },
                    {
                        count: 4,
                        degree: Number(auxiliary.degree),
                        modulus: auxiliary.modulus,
                    },
                ];
                arithmeticKey = `ballot:${profile.optionCount}:${profile.ciphertext.modulus}`;
                break;
            }
            case 'release': {
                const layout = compileLinkedReleaseColumnLayout(profile);
                wordColumns = layout.wordColumns;
                booleanColumns = 2;
                products = 1;
                lookups = layout.lookups;
                const moduli = [
                    sharing.modulus,
                    profile.release.modulus,
                ].flatMap((modulus) => {
                    const bytes = Math.ceil(width(modulus) / 4) * 4;
                    return [
                        BigInt(bytes),
                        ...Array.from(
                            { length: bytes / 4 },
                            (_, index) =>
                                (modulus >> BigInt(32 * index)) & 0xffffffffn,
                        ),
                    ];
                });
                parameters = [
                    wordColumns,
                    booleanColumns,
                    lookups.length,
                    sharing.encryptionSupportWeight,
                    96,
                    48,
                    profile.interpolation.clearingFactor,
                    profile.releaseLifting.publicLimbs,
                    ...layout.columns.map((column) => column.bits),
                    sharing.scale,
                    ...moduli,
                ];
                header = Buffer.from('LRS1');
                families = [
                    { count: 4, degree, modulus: sharing.modulus },
                    { count: 2, degree, modulus: profile.release.modulus },
                ];
                arithmeticKey = `release:${parameters.join(',')}`;
                break;
            }
        }
        const columns = wordColumns + booleanColumns;
        const originalOracles = columns + lookups.length + 4;
        const oracles =
            originalOracles + booleanColumns + products + lookups.length + 2;
        const witnessDegree = degree + agreement.maskDimension - 1;
        const degrees = [
            ...Array.from({ length: originalOracles - 1 }, () => witnessDegree),
            degree + agreement.maskDimension - 2,
            ...Array.from(
                { length: oracles - originalOracles - 2 },
                () => 2 * witnessDegree - degree,
            ),
            witnessDegree - 1,
            degree - 2,
        ];
        const encodedParameters = words([
            degree,
            agreement.queries,
            agreement.maskDimension,
            agreement.domainSize,
            2 * degree - 1,
            2,
            hash.messageBytes,
            ...parameters,
            ...degrees,
            ...lookups.flatMap(({ column, factor }) => [
                BigInt(column),
                factor,
            ]),
        ]);
        if (BigInt(encodedParameters.length) !== hash.parameterBytes)
            throw new Error(
                'Catalogue and hash census parameter lengths differ.',
            );
        return {
            ...hash,
            profile: `${profile.participantCount}/${profile.optionCount}`,
            participantCount: profile.participantCount,
            optionCount: profile.optionCount,
            arithmeticKey,
            encodedParameters,
            header,
            families,
        };
    });

export type ProofRelationCatalogueEntry = ReturnType<
    typeof proofRelationCatalogueEntry
>[number];
let catalogue: readonly ProofRelationCatalogueEntry[] | undefined;
export const proofRelationCatalogue = () =>
    (catalogue ??= listSupportedProfiles().flatMap(
        proofRelationCatalogueEntry,
    ));

// Checks the actual context operands and complete centered-polynomial grammar.
// It does not decide arithmetic truth, authenticate the PID or infer omitted
// roster/provenance predicates. Compatible profiles may be aliases.
export const resolveProofContext = (fields: readonly Buffer[]) => {
    if (
        fields.length !== 7 ||
        !fields[1].equals(proofCatalogueInteger(2n, 16)) ||
        !fields[2].equals(proofCatalogueInteger(field.transformRoot, 16)) ||
        !fields[3].equals(proofCatalogueInteger(7n, 16)) ||
        !fields[5].equals(proofCatalogueInteger(field.modulus - 1n, 16))
    )
        return [];
    const canonicalPayloads = new Map<string, boolean>();
    return proofRelationCatalogue().filter((entry) => {
        if (
            !fields[0].equals(Buffer.from(entry.relationTag)) ||
            !fields[4].equals(entry.encodedParameters) ||
            BigInt(fields[6].length) !== entry.statementBytes
        )
            return false;
        const statement = fields[6];
        if (!statement.subarray(0, entry.header.length).equals(entry.header))
            return false;
        let offset = entry.header.length;
        if (entry.role === 'ballot') {
            if (
                statement.readUInt16LE(132) >= entry.participantCount ||
                statement[134] !== entry.optionCount ||
                statement[135] === 0 ||
                statement[135] > entry.optionCount
            )
                return false;
            offset = 136;
        } else if (entry.role === 'release') {
            if (statement.readUInt16LE(196) >= entry.participantCount)
                return false;
            offset = 198;
        }
        const payloadKey = `${offset}:${entry.families.map((family) => `${family.count}/${family.degree}/${family.modulus}`).join(';')}`;
        const known = canonicalPayloads.get(payloadKey);
        if (known !== undefined) return known;
        const refused = () => {
            canonicalPayloads.set(payloadKey, false);
            return false;
        };
        for (const family of entry.families) {
            const bytes = width(family.modulus);
            const half = proofCatalogueInteger(family.modulus / 2n, bytes);
            for (
                let coefficient = 0;
                coefficient < family.count * family.degree;
                coefficient++
            ) {
                const sign = statement[offset++];
                let comparison = 0,
                    nonzero = false;
                for (let index = bytes - 1; index >= 0; index--) {
                    const value = statement[offset + index];
                    nonzero ||= value !== 0;
                    if (comparison === 0)
                        comparison = Math.sign(value - half[index]);
                }
                if (sign > 1 || comparison > 0 || (sign === 1 && !nonzero))
                    return refused();
                offset += bytes;
            }
        }
        const canonical = offset === statement.length;
        canonicalPayloads.set(payloadKey, canonical);
        return canonical;
    });
};
