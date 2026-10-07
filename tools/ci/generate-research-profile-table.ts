import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { encodeResearchProfileTable } from '#tests/research-profile-table-model.js';

// The tracked table's correspondence test rebuilds it from the same models.
const usage = 'Usage: generate-research-profile-table.ts --output <file>';

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const argumentsList =
        rawArguments[0] === '--' ? rawArguments.slice(1) : rawArguments;
    const [mode, target] = argumentsList;
    if (
        argumentsList.length !== 2 ||
        mode !== '--output' ||
        target === undefined
    )
        throw new Error(usage);
    const targetPath = path.resolve(target);
    const table = encodeResearchProfileTable();
    await writeFile(targetPath, table);
    process.stdout.write(
        `Wrote ${String(table.length)} bytes to ${targetPath}\n`,
    );
};

if (import.meta.main) await main();
