const filesystemRetryDelayMilliseconds = 50;
export const filesystemMaximumRetries = 12;

const transientFilesystemErrorCodes = new Set([
    'ENOENT',
    'EPERM',
    'EACCES',
    'EBUSY',
    'ENOTEMPTY',
    'EMFILE',
    'ENFILE',
]);

const delayMilliseconds = (milliseconds: number): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, milliseconds);
    });

const isTransientFilesystemError = (error: unknown): boolean => {
    const errorCode = (error as NodeJS.ErrnoException).code;

    return (
        errorCode !== undefined && transientFilesystemErrorCodes.has(errorCode)
    );
};

export const withTransientFilesystemRetries = async <ResultType>(
    operation: () => Promise<ResultType>,
    delay: (milliseconds: number) => Promise<void> = delayMilliseconds,
): Promise<ResultType> => {
    for (let attempt = 1; ; attempt += 1) {
        try {
            return await operation();
        } catch (error) {
            if (
                attempt >= filesystemMaximumRetries ||
                !isTransientFilesystemError(error)
            ) {
                throw error;
            }
            await delay(filesystemRetryDelayMilliseconds * attempt);
        }
    }
};
