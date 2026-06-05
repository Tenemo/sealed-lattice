import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const isDirectlyInvokedModule = (
    importMetaUrl: string,
    scriptEntryPoint: string | undefined = process.argv[1],
): boolean =>
    scriptEntryPoint !== undefined &&
    importMetaUrl === pathToFileURL(path.resolve(scriptEntryPoint)).href;
