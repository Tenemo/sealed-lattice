import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { sha256Hex } from '#root';

type TextVectorInput = {
    kind: 'text';
    value: string;
};

type HexVectorInput = {
    kind: 'hex';
    value: string;
};

type RepeatTextVectorInput = {
    count: number;
    kind: 'repeat-text';
    value: string;
};

type CoreVectorInput = TextVectorInput | HexVectorInput | RepeatTextVectorInput;

type CoreVectorDefinition = {
    id: string;
    input: CoreVectorInput;
};

type CoreVector = CoreVectorDefinition & {
    expected: string;
};

const repoRoot = process.cwd();
const outputPath = path.resolve(repoRoot, 'test-vectors/core.json');
const vectorDefinitions: readonly CoreVectorDefinition[] = [
    {
        id: 'empty-string',
        input: {
            kind: 'text',
            value: '',
        },
    },
    {
        id: 'ascii-text',
        input: {
            kind: 'text',
            value: 'sealed-lattice phase one',
        },
    },
    {
        id: 'unicode-text',
        input: {
            kind: 'text',
            value: 'zażółć gęślą jaźń',
        },
    },
    {
        id: 'raw-bytes',
        input: {
            kind: 'hex',
            value: '00ff1020aabbccdd',
        },
    },
    {
        id: 'repeated-text',
        input: {
            kind: 'repeat-text',
            value: 'lattice-',
            count: 128,
        },
    },
] as const;

const expandInput = (input: CoreVectorInput): string | Uint8Array => {
    switch (input.kind) {
        case 'text':
            return input.value;
        case 'hex':
            return Uint8Array.from(
                input.value
                    .match(/.{1,2}/g)
                    ?.map((chunk) => Number.parseInt(chunk, 16)) ?? [],
            );
        case 'repeat-text':
            return input.value.repeat(input.count);
    }
};

const main = async (): Promise<void> => {
    const vectors: CoreVector[] = [];

    for (const vectorDefinition of vectorDefinitions) {
        vectors.push({
            ...vectorDefinition,
            expected: await sha256Hex(expandInput(vectorDefinition.input)),
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
