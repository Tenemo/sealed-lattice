import {
    type PublicKeyShareSuccinctProofRecord,
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

    const proofRecords = input.proofMaterials.map(
        (proofMaterial, trusteeRosterPosition) => {
            assertProtocolHash(
                proofMaterial.proofBytesHash,
                `proofMaterials.${String(trusteeRosterPosition)}.proofBytesHash`,
            );

            return {
                objectType: 'PublicKeyShareSuccinctProof',
                proofBytesHash: proofMaterial.proofBytesHash,
            } satisfies PublicKeyShareSuccinctProofRecord;
        },
    );

    return {
        objectType: 'PublicKeyShareSuccinctProofSet',
        proofRecords,
    } satisfies PublicKeyShareSuccinctProofSet;
};
