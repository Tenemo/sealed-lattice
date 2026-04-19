const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;

export const readPlaceholderKernelFile = async (
    fileUrl: URL,
): Promise<ArrayBuffer> => {
    const [{ readFile }, { fileURLToPath }] = await Promise.all([
        import('node:fs/promises'),
        import('node:url'),
    ]);
    const bytes = await readFile(fileURLToPath(fileUrl));

    return toArrayBuffer(bytes);
};
