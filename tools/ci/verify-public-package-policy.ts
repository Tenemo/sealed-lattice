import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { extractModuleSpecifiers } from '#tools/internal/module-specifiers.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const sdkOutputDirectoryPath = path.resolve(
    repositoryRoot,
    'packages',
    'sdk',
    'dist',
);
const unresolvedKernelHashToken =
    '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';

export const validatePublicPackageBundle = ({
    declarationSourceText,
    runtimeSourceText,
}: {
    readonly declarationSourceText: string;
    readonly runtimeSourceText: string;
}): string[] => {
    const failures: string[] = [];

    for (const [outputLabel, sourceText] of [
        ['runtime', runtimeSourceText],
        ['declaration', declarationSourceText],
    ] as const) {
        for (const moduleSpecifier of extractModuleSpecifiers(sourceText)) {
            if (moduleSpecifier.startsWith('@sealed-lattice/')) {
                failures.push(
                    `Published ${outputLabel} output must bundle internal workspace import "${moduleSpecifier}"`,
                );
            }
        }
    }

    if (runtimeSourceText.includes(unresolvedKernelHashToken)) {
        failures.push(
            'Published runtime output contains the unresolved WASM integrity token',
        );
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

const main = async (): Promise<void> => {
    const [runtimeSourceText, declarationSourceText] = await Promise.all([
        readFile(path.join(sdkOutputDirectoryPath, 'index.js'), 'utf8'),
        readFile(path.join(sdkOutputDirectoryPath, 'index.d.ts'), 'utf8'),
    ]);
    const failures = validatePublicPackageBundle({
        declarationSourceText,
        runtimeSourceText,
    });

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Public package bundle verification passed.');
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
