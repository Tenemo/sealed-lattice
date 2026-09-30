import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

// A repository file relative to the repository root with forward slashes, or
// a refusal when the path lies outside the repository.
const repositoryFile = (absolutePath: string): string => {
    const relative = path.relative(repositoryRoot, path.resolve(absolutePath));
    if (
        relative.length === 0 ||
        relative.startsWith('..') ||
        path.isAbsolute(relative)
    )
        throw new Error(
            'A compiled input lies outside the repository: ' + absolutePath,
        );
    return relative.split(path.sep).join('/');
};

// The repository files a cargo dependency-information file names as its
// artifact's inputs: every source and included file of the workspace's
// crates that the compiler read.
export const compiledRustSources = async (
    dependencyInformationPath: string,
): Promise<string[]> => {
    const [rule] = (await readFile(dependencyInformationPath, 'utf8')).split(
        /\r?\n/u,
    );
    const separator = rule.indexOf(': ');
    if (separator < 0)
        throw new Error(
            'Malformed dependency information: ' + dependencyInformationPath,
        );
    return rule
        .slice(separator + 2)
        .replace(/\\ /gu, '\0')
        .split(' ')
        .filter((name) => name.length > 0)
        .map((name) => repositoryFile(name.replace(/\0/gu, ' ')));
};

// A bundler plugin that records every module the bundle read. The foundation
// bridge enters a bundle as its compiled output, so each output file is
// recorded as the source its compiler maps to it.
export const recordBundleSources = () => {
    const sources: string[] = [];
    const bridgeOutput = 'packages/wasm/dist/';
    return {
        sources,
        plugin: {
            name: 'record-bundle-sources',
            buildEnd(this: { getModuleIds(): IterableIterator<string> }) {
                for (const id of this.getModuleIds()) {
                    const file = repositoryFile(id);
                    if (file.startsWith(bridgeOutput) && file.endsWith('.js'))
                        sources.push(
                            'packages/wasm/src/' +
                                file.slice(bridgeOutput.length, -3) +
                                '.ts',
                        );
                    else if (
                        file.startsWith('packages/') &&
                        !file.includes('/node_modules/') &&
                        !file.includes('/dist/')
                    )
                        sources.push(file);
                    else
                        throw new Error(
                            'A bundle read a module that is not a repository source: ' +
                                file,
                        );
                }
            },
        },
    };
};

// Refuses a listed file that git neither tracks nor leaves unignored, and one
// whose working-tree line endings differ from those a checkout writes, so a
// manifest names bytes that a clean checkout of the same sources reproduces.
export const requireCheckoutBytes = (
    files: readonly string[],
    root = repositoryRoot,
): void => {
    const result = spawnSync(
        'git',
        [
            'ls-files',
            '--eol',
            '--cached',
            '--others',
            '--exclude-standard',
            '-z',
        ],
        {
            cwd: root,
            encoding: 'utf8',
            maxBuffer: 64 << 20,
            windowsHide: true,
        },
    );
    if (result.error !== undefined) throw result.error;
    if (result.status !== 0)
        throw new Error('The repository files could not be listed.');
    const workingTree = new Map<string, string>();
    for (const entry of result.stdout.split('\0')) {
        const tab = entry.indexOf('\t');
        if (tab < 0) continue;
        const [, workingTreeEnding = ''] = entry.slice(0, tab).split(/\s+/u);
        workingTree.set(entry.slice(tab + 1), workingTreeEnding);
    }
    for (const file of files) {
        const ending = workingTree.get(file);
        if (ending === undefined)
            throw new Error(
                'A compiled input is ignored by git or missing: ' + file,
            );
        if (ending === 'w/crlf' || ending === 'w/mixed')
            throw new Error(
                'A compiled input has line endings that a checkout converts: ' +
                    file,
            );
    }
};
