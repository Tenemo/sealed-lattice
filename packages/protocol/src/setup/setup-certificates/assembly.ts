import {
    assertObjectRecord,
    hashArrayField,
    hashField,
    setupCertificateTransportedObjectInputs,
} from './field-helpers.js';
import { setupParametersForCertificates } from './parameter-derivations.js';
import { createSetupTransportCertificate } from './transport-certificate.js';
import type { SetupCertificates, SetupCertificatesInput } from './types.js';

export const createSetupCertificates = (
    input: SetupCertificatesInput,
): SetupCertificates => {
    const setupParameters = setupParametersForCertificates(
        input.setupParameters,
    );
    const transport = assertObjectRecord(input.transport, 'transport');
    const transportInput = {
        fullObjectHash: hashField(transport, 'fullObjectHash', 'transport'),
        chunkHashes: hashArrayField(transport, 'chunkHashes', 'transport'),
        transportedObjects: setupCertificateTransportedObjectInputs(transport),
    };

    return {
        setupTransportCertificate: createSetupTransportCertificate(
            setupParameters,
            transportInput,
        ),
    };
};
