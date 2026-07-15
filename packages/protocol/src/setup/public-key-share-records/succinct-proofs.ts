import {
    type PublicKeyShareSuccinctProofSet,
    type PublicKeyShareSuccinctProofSetInput,
} from './constants-and-types.js';
import { assertProtocolHash } from './encoding.js';

export const createPublicKeyShareSuccinctProofSet = (
    input: PublicKeyShareSuccinctProofSetInput,
): PublicKeyShareSuccinctProofSet => {
    if (input.proofMaterials.length !== input.setupContext.participantCount) {
        throw new Error(
            'public-key share proof materials must contain one proof per participant in roster order.',
        );
    }

    const proofBytesHashes = input.proofMaterials.map(
        (proofMaterial, trusteeRosterPosition) => {
            assertProtocolHash(
                proofMaterial.proofBytesHash,
                `proofMaterials.${String(trusteeRosterPosition)}.proofBytesHash`,
            );
            return proofMaterial.proofBytesHash;
        },
    );

    return {
        objectType: 'PublicKeyShareSuccinctProofSet',
        proofBytesHashes,
    } satisfies PublicKeyShareSuccinctProofSet;
};
