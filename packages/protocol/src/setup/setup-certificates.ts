// Barrel for the collective BGV setup certificate builder. The implementation
// lives in the cohesive sub-modules under ./setup-certificates/, grouped by the
// domain problem each part solves: shared certificate vocabulary and types,
// transport/hash-namespace constants, field validation and modulus-bound math
// helpers, setup and BGV parameter derivations, the setup transport certificate
// builder, and the certificate-set assembly entry point.
export { createSetupCertificates } from './setup-certificates/assembly.js';
export type {
    BgvRnsParametersForCertificates,
    CollectiveBgvSetupParametersForCertificates,
    SetupCertificateTransportedObjectInput,
    SetupCertificateTransportInput,
    SetupCertificates,
    SetupCertificatesInput,
    SetupTransportCertificate,
} from './setup-certificates/types.js';
