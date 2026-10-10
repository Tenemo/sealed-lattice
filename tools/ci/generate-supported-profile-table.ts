import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { encodeSupportedProfileTable } from '#tests/supported-profile-table-model.js';
import { toolArguments } from '#tools/ci/command-line.js';

// The tracked table's correspondence test rebuilds it from the same models.
const usage = 'Usage: generate-supported-profile-table.ts --output <file>';

const main = async (): Promise<void> => {
    const argumentsList = toolArguments(process.argv.slice(2));
    const [mode, target] = argumentsList;
    if (
        argumentsList.length !== 2 ||
        mode !== '--output' ||
        target === undefined
    )
        throw new Error(usage);
    const targetPath = path.resolve(target);
    const table = encodeSupportedProfileTable();
    await writeFile(targetPath, table);
    process.stdout.write(
        `Wrote ${String(table.length)} bytes to ${targetPath}\n`,
    );
};

if (import.meta.main) await main();
