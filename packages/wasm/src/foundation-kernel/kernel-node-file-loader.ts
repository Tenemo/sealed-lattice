type NodeFileSystemPromises = {
    readonly readFile: (fileUrl: URL) => Promise<Uint8Array>;
};
const nodeFileSystemPromisesModuleSpecifier = 'node:fs/promises';

export const readNodeFileAsArrayBuffer = async (
    fileUrl: URL,
): Promise<ArrayBuffer> => {
    // This module is reached only for file: URLs in Node.
    const nodeFileSystemPromises = (await import(
        /* @vite-ignore */ nodeFileSystemPromisesModuleSpecifier
    )) as NodeFileSystemPromises;
    const bytes = await nodeFileSystemPromises.readFile(fileUrl);

    return Uint8Array.from(bytes).buffer;
};
