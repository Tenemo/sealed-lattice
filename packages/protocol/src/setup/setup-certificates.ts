// Barrel for the collective BGV setup certificate builders. The implementation
// lives in the cohesive sub-modules under ./setup-certificates/, grouped by the
// domain problem each part solves: shared certificate vocabulary and types,
// transport/hash-namespace constants, field validation and modulus-bound math
// helpers, setup and BGV parameter derivations, and one builder per certificate
// (commitment security, proof accounting, transport, and BGV HE security) plus
// the certificate-set assembly entry point. This file keeps the original import
// path and public surface unchanged.
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
