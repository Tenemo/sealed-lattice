// Barrel for the collective BGV setup package assembler. The implementation
// lives in the cohesive sub-modules under ./setup-package-assembly/, grouped by
// the domain problem each part solves: shared package and certificate types,
// parameter constants and structural assertion helpers, verification-input and
// hash-input derivation, the input binding validation cluster, transported
// material accounting for the setup transport certificate, the setup transport
// certificate resolution and collective public key derivation, and the package
// assembly entry point. This file keeps the original import path and public
// surface unchanged.
export { createSetupPackage } from './setup-package-assembly/assembly.js';
export {
    createSetupPackageVerificationInput,
    setupPackageHashInput,
} from './setup-package-assembly/verification-input.js';
export type {
    SetupPackage,
    SetupPackageCertificateInput,
    SetupPackageInput,
    SetupPackageVerificationInput,
    SetupPackageVerificationInputSource,
} from './setup-package-assembly/types.js';
