/**
 * Typed placeholder kernel wrapper.
 *
 * The Rust crate currently exports one trivial function so the workspace can
 * prove the WASM build and loading path before any cryptographic arithmetic is
 * introduced.
 */

export type PlaceholderKernel = {
    readonly exportedFunctionNames: readonly string[];
    getPlaceholderValue(): number;
};

type PlaceholderKernelExports = WebAssembly.Exports & {
    sealed_lattice_placeholder_value?: () => number;
};

const placeholderKernelUrl = new URL(
    '../dist/sealed-lattice-kernel-placeholder.wasm',
    import.meta.url,
);

const resolvePlaceholderBytes = async (): Promise<ArrayBuffer> => {
    /* v8 ignore next */
    if (placeholderKernelUrl.protocol === 'file:') {
        const { readPlaceholderKernelFile } =
            await import('./node-placeholder-kernel.js');

        return readPlaceholderKernelFile(placeholderKernelUrl);
    }

    /* v8 ignore start */
    const response = await fetch(placeholderKernelUrl);
    if (!response.ok) {
        throw new Error(
            `Failed to fetch placeholder kernel from ${placeholderKernelUrl.toString()}.`,
        );
    }

    return response.arrayBuffer();
    /* v8 ignore stop */
};

const resolvePlaceholderExport = (
    exports: PlaceholderKernelExports,
): (() => number) => {
    const exportValue = exports.sealed_lattice_placeholder_value;
    /* v8 ignore next 3 */
    if (typeof exportValue !== 'function') {
        throw new Error(
            'The placeholder kernel did not expose sealed_lattice_placeholder_value.',
        );
    }

    return (): number => Number(exportValue());
};

export const loadPlaceholderKernel = async (): Promise<PlaceholderKernel> => {
    const bytes = await resolvePlaceholderBytes();
    const instantiatedSource = await WebAssembly.instantiate(bytes, {});
    const getPlaceholderValue = resolvePlaceholderExport(
        instantiatedSource.instance.exports as PlaceholderKernelExports,
    );
    const exportedFunctionNames = WebAssembly.Module.exports(
        instantiatedSource.module,
    )
        .map((entry) => entry.name)
        .sort();

    return {
        exportedFunctionNames,
        getPlaceholderValue,
    };
};

export const loadPlaceholderValue = async (): Promise<number> => {
    const kernel = await loadPlaceholderKernel();

    return kernel.getPlaceholderValue();
};
