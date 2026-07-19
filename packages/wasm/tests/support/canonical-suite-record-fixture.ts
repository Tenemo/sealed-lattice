import { createSuiteArtifactHashAccumulator } from '#packages/wasm/src/runtime-build-canonical';
import {
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    hashItem,
    unsigned16Item,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';

const orderedDataPrimes = [
    1_953_759_233n,
    2_256_928_769n,
    2_408_513_537n,
    2_610_626_561n,
    2_661_154_817n,
    3_014_852_609n,
    3_031_695_361n,
    3_368_550_401n,
    84_213_761n,
    235_798_529n,
    336_855_041n,
    1_010_565_121n,
    690_552_833n,
    1_313_734_657n,
    1_397_948_417n,
    437_911_553n,
    404_226_049n,
    606_339_073n,
    1_061_093_377n,
    1_819_017_217n,
    555_810_817n,
    1_869_545_473n,
    1_903_230_977n,
] as const;

const orderedSpecialPrimes = [
    275_513_737_217n,
    275_530_579_969n,
    275_968_491_521n,
] as const;

const orderedTargetAndSharingDataPrimeIndexes = [
    0, 1, 2, 3, 4, 5, 6, 7,
] as const;

const unsigned32Item = (value: number): Uint8Array =>
    canonicalItem(0x04, unsigned32LittleEndian(value));

const unsigned64LittleEndian = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const homogeneousListItem = (
    itemType: number,
    values: readonly Uint8Array[],
): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(itemType),
            unsigned32LittleEndian(values.length),
            ...values,
        ),
    );

const artifactReference = (
    artifactKind: number,
    artifactBytes: Uint8Array,
): Uint8Array => {
    const hash = createSuiteArtifactHashAccumulator(
        artifactKind,
        BigInt(artifactBytes.byteLength),
    );
    hash.update(artifactBytes);
    return canonicalTuple(
        0x0117,
        unsigned16Item(artifactKind),
        unsigned64Item(BigInt(artifactBytes.byteLength)),
        hashItem(hash.finish()),
    );
};

type CanonicalSuiteRecordFixtureInput = Readonly<{
    artifactBytes?: readonly Uint8Array[];
    polynomialDegree?: number;
}>;

export const createCanonicalSuiteRecordFixture = (
    input: CanonicalSuiteRecordFixtureInput = {},
): Uint8Array => {
    const artifactBytes =
        input.artifactBytes ??
        Array.from({ length: 6 }, (_unused, artifactIndex) =>
            Uint8Array.of(artifactIndex + 1),
        );
    const polynomialDegree = input.polynomialDegree ?? 32_768;
    if (
        artifactBytes.length !== 6 ||
        artifactBytes.some(
            (bytes) => !(bytes instanceof Uint8Array) || bytes.byteLength === 0,
        )
    ) {
        throw new TypeError(
            'The canonical suite fixture requires six nonempty artifact byte strings.',
        );
    }
    if (
        !Number.isInteger(polynomialDegree) ||
        polynomialDegree < 0 ||
        polynomialDegree > 0xffff_ffff
    ) {
        throw new RangeError(
            'The canonical suite fixture polynomial degree must fit unsigned 32-bit encoding.',
        );
    }
    const ternaryPurposes = new Set([1, 3, 8, 11, 12]);
    const distributions = Array.from({ length: 12 }, (_value, index) => {
        const purpose = index + 1;
        const isTernary = ternaryPurposes.has(purpose);
        return canonicalTuple(
            0x0116,
            unsigned16Item(purpose),
            unsigned16Item(isTernary ? 1 : 2),
            unsigned64Item(isTernary ? 0n : 2n),
        );
    });

    return canonicalTuple(
        0x0118,
        unsigned16Item(2),
        unsigned16Item(10),
        unsigned16Item(3),
        unsigned16Item(4),
        unsigned16Item(7),
        unsigned32Item(polynomialDegree),
        unsigned64Item(257n),
        homogeneousListItem(
            0x05,
            orderedDataPrimes.map(unsigned64LittleEndian),
        ),
        homogeneousListItem(
            0x05,
            orderedSpecialPrimes.map(unsigned64LittleEndian),
        ),
        homogeneousListItem(
            0x03,
            orderedTargetAndSharingDataPrimeIndexes.map(unsigned16LittleEndian),
        ),
        homogeneousListItem(
            0x03,
            orderedTargetAndSharingDataPrimeIndexes.map(unsigned16LittleEndian),
        ),
        unsigned16Item(1),
        unsigned16Item(3),
        unsigned16Item(1),
        unsigned16Item(3),
        unsigned16Item(10),
        unsigned32Item(64),
        unsigned32Item(128),
        unsigned32Item(20),
        unsigned32Item(103),
        homogeneousListItem(0x09, distributions),
        homogeneousListItem(
            0x09,
            artifactBytes.map((bytes, artifactIndex) =>
                artifactReference(artifactIndex + 1, bytes),
            ),
        ),
    );
};
