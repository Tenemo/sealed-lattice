import {
    assertObjectRecord,
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
        transportedObjects: setupCertificateTransportedObjectInputs(transport),
    };

    return {
        setupTransportCertificate: createSetupTransportCertificate(
            setupParameters,
            transportInput,
        ),
    };
};
