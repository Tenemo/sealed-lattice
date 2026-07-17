import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    type BinaryChunkedPublicKeyShareMaterialBundle,
    type BinaryChunkedPublicKeyShareMaterialBundleInput,
    type BinaryChunkedPublicKeyShareMaterialSet,
    type PublicKeyShareMaterialStream,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareSet,
} from './constants-and-types.js';
import {
    assertPublicKeyShareMaterialInput,
    createPublicKeyShareMaterialEncodingSource,
    derivePublicKeyShareMaterialRoot,
    publicKeyShareMaterialRecordsFromContributions,
} from './embedded-material-records.js';
import { deriveCollectiveBgvSetupContextHash } from './encoding.js';
import { derivePublicKeyShareSetRoot } from './share-statement-records.js';

const binaryChunkedPublicKeyShareMaterialSet = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyShares: PublicKeyShareSet;
        readonly publicKeyShareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
    }>,
): BinaryChunkedPublicKeyShareMaterialSet => {
    const publicKeyShareMaterialRoots = input.publicKeyShareMaterialRecords.map(
        (materialRecord, trusteeRosterPosition) => {
            const shareRecord =
                input.publicKeyShares.shareRecords[trusteeRosterPosition];
            if (shareRecord === undefined) {
                throw new Error(
                    'public-key share material must have one accepted share record per trustee.',
                );
            }

            return derivePublicKeyShareMaterialRoot(
                input,
                trusteeRosterPosition,
                shareRecord,
                materialRecord,
            );
        },
    );
    return {
        objectType: 'PublicKeyShareMaterialSet',
        publicKeyShareMaterialSetRoot: deriveCanonicalObjectHash({
            objectType: 'PublicKeyShareMaterialSet',
            setupContextHash: deriveCollectiveBgvSetupContextHash(
                input.setupContext,
            ),
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            publicKeyShareSetRoot: derivePublicKeyShareSetRoot(
                input.setupContext,
                input.publicMatrixSeedHash,
                input.publicKeyShares,
            ),
            publicKeyShareMaterialRoots: publicKeyShareMaterialRoots.map(
                (publicKeyShareMaterialRoot, trusteeRosterPosition) => {
                    return {
                        trusteeRosterPosition,
                        publicKeyShareMaterialRoot,
                    };
                },
            ),
        }),
    } satisfies BinaryChunkedPublicKeyShareMaterialSet;
};

const finishPublicKeyShareMaterialTransport = async (
    materialSet: BinaryChunkedPublicKeyShareMaterialSet,
    encodingSource: Readonly<{
        readonly pullChunk: PublicKeyShareMaterialStream['pullChunk'];
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
    return {
        materialSet,
        publicKeyShareMaterialStream: {
            descriptorBytes,
            pullChunk: encodingSource.pullChunk,
        },
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
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyShares: input.publicKeyShares,
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
