import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { exit } from 'node:process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
);
const sourceDirectories = ['src'];
const offenders: string[] = [];

const walk = async (directory: string): Promise<void> => {
    let entries;

    try {
        entries = await readdir(directory, { withFileTypes: true });
    } catch {
        return;
    }

    for (const entry of entries) {
        const entryPath = path.join(directory, entry.name);

        if (entry.isDirectory()) {
            await walk(entryPath);
            continue;
        }

        if (!entry.isFile() || !entry.name.endsWith('.ts')) {
            continue;
        }

        const contents = await readFile(entryPath, 'utf8');
        if (contents.includes('Math.random')) {
            offenders.push(path.relative(repoRoot, entryPath));
        }
    }
};

for (const relativeDirectory of sourceDirectories) {
    await walk(path.join(repoRoot, relativeDirectory));
}

if (offenders.length > 0) {
    console.error('Math.random() is forbidden in source directories:');
    for (const offender of offenders) {
        console.error(`- ${offender}`);
    }
    exit(1);
}

console.log('No Math.random() usage found in source directories.');
