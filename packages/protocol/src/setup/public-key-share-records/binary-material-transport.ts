import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    type BinaryChunkedPublicKeyShareMaterialBundle,
    type BinaryChunkedPublicKeyShareMaterialBundleInput,
    type BinaryChunkedPublicKeyShareMaterialSet,
    type BinaryChunkedPublicKeyShareMaterialTransport,
    type BinaryChunkedPublicKeyShareMaterialTransportInput,
    type PublicKeyShareMaterialChunkSource,
    type PublicKeyShareMaterialRootReference,
} from './constants-and-types.js';
import {
    assertPublicKeyShareMaterialInput,
    createPublicKeyShareMaterialEncodingSource,
    createPublicKeyShareMaterialSetEncodingSource,
    publicKeyShareMaterialRecordsFromContributions,
    publicKeyShareMaterialRootReferences,
} from './embedded-material-records.js';
import { contextFields } from './encoding.js';

const binaryChunkedPublicKeyShareMaterialSet = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
    }>,
): BinaryChunkedPublicKeyShareMaterialSet => {
    const materialSetWithoutRoot = {
        objectType: 'PublicKeyShareMaterialSet',
        ...contextFields(input.setupContext),
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots: input.publicKeyShareMaterialRoots,
    } as const satisfies Omit<
        BinaryChunkedPublicKeyShareMaterialSet,
        'publicKeyShareMaterialSetRoot'
    >;

    return {
        ...materialSetWithoutRoot,
        publicKeyShareMaterialSetRoot: deriveCanonicalObjectHash(
            materialSetWithoutRoot,
        ),
    } satisfies BinaryChunkedPublicKeyShareMaterialSet;
};

const finishPublicKeyShareMaterialTransport = async (
    materialSet: BinaryChunkedPublicKeyShareMaterialSet,
    encodingSource: Readonly<{
        readonly pullChunk: PublicKeyShareMaterialChunkSource['pullChunk'];
        readonly totalByteLength: number;
    }>,
    writePublicKeyShareMaterial: BinaryChunkedPublicKeyShareMaterialTransportInput['writePublicKeyShareMaterial'],
): Promise<BinaryChunkedPublicKeyShareMaterialTransport> => {
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

export const createBinaryChunkedPublicKeyShareMaterialTransport = async (
    input: BinaryChunkedPublicKeyShareMaterialTransportInput,
): Promise<BinaryChunkedPublicKeyShareMaterialTransport> => {
    const materialSet = binaryChunkedPublicKeyShareMaterialSet({
        setupContext: input.materialSet as unknown as CollectiveBgvSetupContext,
        ringDegree: input.materialSet.ringDegree,
        publicMatrixSeedHash: input.materialSet.publicMatrixSeedHash,
        publicKeyCrpRoot: input.materialSet.publicKeyCrpRoot,
        publicAPolynomialRoot: input.materialSet.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.materialSet.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots: publicKeyShareMaterialRootReferences(
            input.materialSet.shareMaterialRecords,
        ),
    });

    return finishPublicKeyShareMaterialTransport(
        materialSet,
        createPublicKeyShareMaterialSetEncodingSource(
            input.materialSet,
            input.qSharePrimes,
        ),
        input.writePublicKeyShareMaterial,
    );
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
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots:
            publicKeyShareMaterialRootReferences(shareMaterialRecords),
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
