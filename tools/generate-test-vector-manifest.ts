import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    buildVectorManifestFromDirectory,
    vectorManifestPath,
    vectorsRootDirectoryPath,
} from './ci/verify-test-vectors.js';

/* v8 ignore start */
const main = async (): Promise<void> => {
    const manifest = await buildVectorManifestFromDirectory(
        vectorsRootDirectoryPath,
    );
    await writeFile(
        vectorManifestPath,
        `${JSON.stringify(manifest, null, 2)}\n`,
        'utf8',
    );

    console.log(
        `Vector manifest written to ${path.relative(process.cwd(), vectorManifestPath)}`,
    );
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    void main();
}
/* v8 ignore stop */
