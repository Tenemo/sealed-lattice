import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import { preProcessFile } from 'typescript';

import { repositoryRoot } from '#tools/ci/command-line.js';

// The scripts whose imports the walk follows; any other file ends it.
const scriptFileName = /\.(?:[cm]?[jt]s)$/u;

const isFile = async (filePath: string): Promise<boolean> => {
    try {
        return (await stat(filePath)).isFile();
    } catch (error) {
        if (
            error instanceof Error &&
            'code' in error &&
            error.code === 'ENOENT'
        )
            return false;
        throw error;
    }
};

// The workspace's subpath imports: each `#name/*` prefix and its target.
const readSubpathImports = async (root: string) =>
    Object.entries(
        (
            JSON.parse(
                await readFile(path.join(root, 'package.json'), 'utf8'),
            ) as { imports?: Record<string, string> }
        ).imports ?? {},
    ).map(([pattern, target]) => ({
        prefix: pattern.replace(/\*$/u, ''),
        target: target.replace(/\*$/u, ''),
    }));

// A relative or subpath import's file, as tsx resolves it: the named file, or
// the TypeScript source a `.js` or extensionless name stands for. Package and
// built-in imports leave the repository and end the walk.
const resolveImport = async (
    importer: string,
    specifier: string,
    subpathImports: Awaited<ReturnType<typeof readSubpathImports>>,
    root: string,
): Promise<string | undefined> => {
    let target: string;
    if (specifier.startsWith('.')) {
        target = path.resolve(path.dirname(importer), specifier);
    } else if (specifier.startsWith('#')) {
        const subpath = subpathImports.find(({ prefix }) =>
            specifier.startsWith(prefix),
        );
        if (subpath === undefined)
            throw new Error(
                `An import names an undeclared subpath: ${specifier}`,
            );
        target = path.resolve(
            root,
            subpath.target + specifier.slice(subpath.prefix.length),
        );
    } else {
        return undefined;
    }
    for (const candidate of [
        target,
        target.replace(/\.js$/u, '.ts'),
        `${target}.ts`,
    ]) {
        if (await isFile(candidate)) return candidate;
    }
    throw new Error(
        `${path.relative(root, importer)} imports ${specifier}, which names no repository file.`,
    );
};

// The repository files the entry files import, transitively and including the
// entries, as sorted repository paths with forward slashes. A run snapshots
// this closure, so its record cannot omit a source it executed.
export const importClosure = async (
    entries: readonly string[],
    root = repositoryRoot,
): Promise<string[]> => {
    const subpathImports = await readSubpathImports(root);
    const visited = new Set<string>();
    const pending = entries.map((entry) => path.resolve(root, entry));
    for (let file = pending.pop(); file !== undefined; file = pending.pop()) {
        if (visited.has(file)) continue;
        const relative = path.relative(root, file);
        if (relative.startsWith('..') || path.isAbsolute(relative))
            throw new Error(`An import lies outside the repository: ${file}`);
        if (!(await isFile(file)))
            throw new Error(`An entry names no repository file: ${relative}`);
        visited.add(file);
        if (!scriptFileName.test(file)) continue;
        for (const { fileName } of preProcessFile(
            await readFile(file, 'utf8'),
            true,
            true,
        ).importedFiles) {
            const imported = await resolveImport(
                file,
                fileName,
                subpathImports,
                root,
            );
            if (imported !== undefined) pending.push(imported);
        }
    }
    return [...visited]
        .map((file) => path.relative(root, file).split(path.sep).join('/'))
        .sort();
};
