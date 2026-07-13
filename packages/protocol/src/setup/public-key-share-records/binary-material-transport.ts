import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    type BinaryChunkedPublicKeyShareMaterialBundle,
    type BinaryChunkedPublicKeyShareMaterialBundleInput,
    type BinaryChunkedPublicKeyShareMaterialSet,
    type PublicKeyShareMaterialChunkSource,
    type PublicKeyShareMaterialRecord,
} from './constants-and-types.js';
import {
    assertPublicKeyShareMaterialInput,
    createPublicKeyShareMaterialEncodingSource,
    publicKeyShareMaterialRecordsFromContributions,
} from './embedded-material-records.js';
import { deriveCollectiveBgvSetupContextHash } from './encoding.js';

const binaryChunkedPublicKeyShareMaterialSet = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
    }>,
): BinaryChunkedPublicKeyShareMaterialSet => {
    const publicKeyShareMaterialRoots = input.publicKeyShareMaterialRecords.map(
        (materialRecord) => materialRecord.publicKeyShareMaterialRoot,
    );
    const materialSetWithoutRoot = {
        objectType: 'PublicKeyShareMaterialSet',
        publicKeyShareMaterialRoots,
    } as const satisfies Omit<
        BinaryChunkedPublicKeyShareMaterialSet,
        'publicKeyShareMaterialSetRoot'
    >;

    return {
        ...materialSetWithoutRoot,
        publicKeyShareMaterialSetRoot: deriveCanonicalObjectHash({
            objectType: materialSetWithoutRoot.objectType,
            setupContextHash: deriveCollectiveBgvSetupContextHash(
                input.setupContext,
            ),
            ringDegree: input.ringDegree,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            publicKeyShareSetRoot: input.publicKeyShareSetRoot,
            publicKeyShareMaterialRoots:
                input.publicKeyShareMaterialRecords.map((materialRecord) => ({
                    trusteeIdentity: materialRecord.trusteeIdentity,
                    trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                    publicKeyShareMaterialRoot:
                        materialRecord.publicKeyShareMaterialRoot,
                })),
        }),
    } satisfies BinaryChunkedPublicKeyShareMaterialSet;
};

const finishPublicKeyShareMaterialTransport = async (
    materialSet: BinaryChunkedPublicKeyShareMaterialSet,
    encodingSource: Readonly<{
        readonly pullChunk: PublicKeyShareMaterialChunkSource['pullChunk'];
        readonly totalByteLength: number;
    }>,
    writePublicKeyShareMaterial: BinaryChunkedPublicKeyShareMaterialBundleInput['writePublicKeyShareMaterial'],
): Promise<BinaryChunkedPublicKeyShareMaterialBundle> => {
    const descriptorBytes = copyCanonicalStreamDescriptor(
        await writePublicKeyShareMaterial({
            publicKeyShareMaterialSetRoot:
                materialSet.publicKeyShareMaterialSetRoot,
            pullChunk: encodingSource.pullChunk,
            totalByteLength: encodingSource.totalByteLength,
        }),
        'writePublicKeyShareMaterial descriptorBytes',
    );
    const publicKeyShareMaterialChunkSource = {
        publicKeyShareMaterialSetRoot:
            materialSet.publicKeyShareMaterialSetRoot,
        pullChunk: encodingSource.pullChunk,
    } satisfies PublicKeyShareMaterialChunkSource;

    return {
        materialSet,
        transportedPublicKeyShareMaterial: {
            objectType: 'SetupTransportedPublicKeyShareMaterial',
            publicKeyShareMaterialSetRoot:
                materialSet.publicKeyShareMaterialSetRoot,
            descriptorBytes,
        },
        publicKeyShareMaterialChunkSource,
    };
};

export const createBinaryChunkedPublicKeyShareMaterialBundle = async (
    input: BinaryChunkedPublicKeyShareMaterialBundleInput,
): Promise<BinaryChunkedPublicKeyShareMaterialBundle> => {
    assertPublicKeyShareMaterialInput(input);
    const shareMaterialRecords =
        publicKeyShareMaterialRecordsFromContributions(input);
    const materialSet = binaryChunkedPublicKeyShareMaterialSet({
        setupContext: input.setupContext,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareMaterialRecords: shareMaterialRecords,
    });

    return finishPublicKeyShareMaterialTransport(
        materialSet,
        createPublicKeyShareMaterialEncodingSource({
            qSharePrimes: input.qSharePrimes,
            ringDegree: input.ringDegree,
            shareMaterialRecords,
        }),
        input.writePublicKeyShareMaterial,
    );
};
