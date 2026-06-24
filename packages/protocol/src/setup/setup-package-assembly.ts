// Barrel for the collective BGV setup package assembler. The implementation
// lives in the cohesive sub-modules under ./setup-package-assembly/, grouped by
// the domain problem each part solves: shared package and certificate types,
// parameter constants and structural assertion helpers, verification-input and
// hash-input derivation, the input binding validation cluster, transported
// material accounting for the setup certificates, the key-correctness and
// active-static theorem certificate builders, and the package assembly entry
// point. This file keeps the original import path and public surface unchanged.
export { createSetupPackage } from './setup-package-assembly/assembly.js';
export {
    createSetupPackageVerificationInput,
    setupPackageHashInput,
} from './setup-package-assembly/verification-input.js';
export type {
    SetupKeyCorrectnessCertificate,
    SetupPackage,
    SetupPackageCertificateInput,
    SetupPackageInput,
    SetupPackageVerificationInput,
    SetupPackageVerificationInputSource,
} from './setup-package-assembly/types.js';
