// The foundation kernel the SDK package ships beside its entry point and the
// digest its build recorded, when a build recorded one.
export const foundationKernelUrl = new URL(
    './sealed-lattice-kernel.wasm',
    import.meta.url,
);

declare const __SEALED_LATTICE_KERNEL_SHA256_HEX__: string | undefined;

export const foundationKernelSha256 =
    typeof __SEALED_LATTICE_KERNEL_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_SHA256_HEX__;
