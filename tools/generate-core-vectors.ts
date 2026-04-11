import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    coreVectorDefinitions,
    expandCoreVectorInput,
} from '../test-vectors/core';

import { sha256Hex } from '#root';

const repoRoot = process.cwd();
const outputPath = path.resolve(repoRoot, 'test-vectors/core.json');
type CoreVector = {
    expected: string;
} & (typeof coreVectorDefinitions)[number];

const main = async (): Promise<void> => {
    const vectors: CoreVector[] = [];

    for (const vectorDefinition of coreVectorDefinitions) {
        vectors.push({
            ...vectorDefinition,
            expected: await sha256Hex(
                expandCoreVectorInput(vectorDefinition.input),
            ),
        });
    }

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(
        outputPath,
        `${JSON.stringify(
            {
                algorithm: 'SHA-256',
                vectors,
            },
            null,
            2,
        )}\n`,
    );

    console.log(
        `Core vectors written to ${path.relative(repoRoot, outputPath)}`,
    );
};

void main();
