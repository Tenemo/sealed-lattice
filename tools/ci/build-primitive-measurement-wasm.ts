import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    buildOptimizedWasmKernelArtifact,
    type BuiltWasmKernelArtifact,
} from './build-wasm-kernel.js';

const repositoryRootPath = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);

export const primitiveMeasurementWasmOutputFilePath = path.resolve(
    repositoryRootPath,
    'temp',
    'primitive-measurements',
    'sealed-lattice-kernel-primitive-measurement.wasm',
);

export const buildPrimitiveMeasurementWasm =
    async (): Promise<BuiltWasmKernelArtifact> =>
        buildOptimizedWasmKernelArtifact({
            artifactLabel: 'Primitive-measurement kernel',
            cargoFeatures: ['primitive-measurement-evidence'],
            outputFilePath: primitiveMeasurementWasmOutputFilePath,
            scratchDirectoryPrefix: 'primitive-measurement-',
            targetDirectoryPath: path.resolve(
                repositoryRootPath,
                'target',
                'wasm-kernel-primitive-measurements',
            ),
        });

if (import.meta.main) {
    await buildPrimitiveMeasurementWasm();
}
