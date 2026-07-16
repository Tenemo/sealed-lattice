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
    140_700_980_543_489n,
    140_546_359_361_537n,
    140_507_704_066_049n,
    140_417_508_376_577n,
    140_396_033_212_417n,
    140_383_148_113_921n,
    140_365_967_982_593n,
    140_280_067_325_953n,
    140_061_020_651_521n,
    139_992_300_126_209n,
    139_880_629_272_577n,
    139_764_663_386_113n,
    139_708_827_959_297n,
    139_670_172_663_809n,
    139_541_321_678_849n,
    139_451_125_989_377n,
    139_399_585_595_393n,
] as const;

const orderedSpecialPrimes = [
    140_737_487_306_753n,
    140_737_486_716_929n,
    140_737_486_520_321n,
    140_737_485_864_961n,
    140_737_484_685_313n,
    140_737_483_898_881n,
    140_737_482_981_377n,
    140_737_481_801_729n,
    140_737_481_342_977n,
    140_737_480_949_761n,
    140_737_480_359_937n,
    140_737_479_639_041n,
    140_737_476_100_097n,
    140_737_472_299_009n,
    140_737_471_971_329n,
    140_737_471_774_721n,
    140_737_471_578_113n,
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

export const createCanonicalSuiteRecordFixture = (
    artifactBytes: readonly Uint8Array[] = Array.from(
        { length: 6 },
        (_unused, artifactIndex) => Uint8Array.of(artifactIndex + 1),
    ),
): Uint8Array => {
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
        unsigned16Item(1),
        unsigned16Item(10),
        unsigned16Item(3),
        unsigned16Item(4),
        unsigned16Item(7),
        unsigned32Item(32_768),
        unsigned64Item(65_537n),
        homogeneousListItem(
            0x05,
            orderedDataPrimes.map(unsigned64LittleEndian),
        ),
        homogeneousListItem(
            0x05,
            orderedSpecialPrimes.map(unsigned64LittleEndian),
        ),
        homogeneousListItem(0x03, [0, 1].map(unsigned16LittleEndian)),
        homogeneousListItem(
            0x03,
            Array.from({ length: 17 }, (_value, index) =>
                unsigned16LittleEndian(index),
            ),
        ),
        unsigned16Item(1),
        unsigned16Item(orderedSpecialPrimes.length),
        unsigned16Item(1),
        unsigned16Item(3),
        unsigned16Item(10),
        unsigned32Item(64),
        unsigned32Item(128),
        unsigned32Item(20),
        unsigned32Item(100),
        unsigned64Item(3_000n),
        unsigned64Item(20_000n),
        unsigned64Item(5_000n),
        unsigned64Item(25_000n),
        unsigned64Item(50_000n),
        unsigned64Item(10_000n),
        unsigned64Item(100_000n),
        homogeneousListItem(0x09, distributions),
        homogeneousListItem(
            0x09,
            artifactBytes.map((bytes, artifactIndex) =>
                artifactReference(artifactIndex + 1, bytes),
            ),
        ),
    );
};
