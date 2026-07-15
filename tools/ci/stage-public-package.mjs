import { copyFile, cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

/** @param {string} packageJsonText */
const sanitizePublicPackageJson = (packageJsonText) => {
    const packageJson = JSON.parse(packageJsonText);
    delete packageJson.devDependencies;
    delete packageJson.scripts;

    return `${JSON.stringify(packageJson, null, 4)}\n`;
};

/** @param {string} destinationPath */
export const stagePublicPackage = async (destinationPath) => {
    const packageDirectory = path.resolve(repositoryRoot, 'packages', 'sdk');
    const resolvedDestinationPath = path.resolve(destinationPath);
    await mkdir(resolvedDestinationPath);

    await Promise.all([
        cp(
            path.join(packageDirectory, 'dist'),
            path.join(resolvedDestinationPath, 'dist'),
            { recursive: true },
        ),
        writeFile(
            path.join(resolvedDestinationPath, 'package.json'),
            sanitizePublicPackageJson(
                await readFile(
                    path.join(packageDirectory, 'package.json'),
                    'utf8',
                ),
            ),
            'utf8',
        ),
        copyFile(
            path.join(repositoryRoot, 'README.md'),
            path.join(resolvedDestinationPath, 'README.md'),
        ),
        copyFile(
            path.join(repositoryRoot, 'LICENSE'),
            path.join(resolvedDestinationPath, 'LICENSE'),
        ),
    ]);
};
