import { mkdir, open, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

// The guarded relay accepts exact re-forwarding from any participant while
// preserving the first publisher's append authority. Serialize each path so
// simultaneous certificate publications cannot both append to an empty file.
export const participantRelayWriter = (owners: Map<string, string>) => {
    const pending = new Map<string, Promise<void>>();
    return async (
        file: string,
        origin: string,
        offset: number,
        bytes: Buffer,
    ) => {
        const previous = pending.get(file);
        let unlock!: () => void;
        const released = new Promise<void>((resolve) => {
            unlock = resolve;
        });
        pending.set(file, released);
        await previous;
        try {
            const existing = await stat(file).catch((error: unknown) => {
                if (
                    error !== null &&
                    typeof error === 'object' &&
                    'code' in error &&
                    error.code === 'ENOENT'
                )
                    return undefined;
                throw error;
            });
            const length = existing?.size ?? 0;
            if (
                !Number.isSafeInteger(offset) ||
                offset < 0 ||
                offset > length ||
                ((owners.get(file) ?? origin) !== origin &&
                    offset + bytes.length > length)
            )
                return false;
            if (offset < length) {
                if (bytes.length > length - offset) return false;
                const handle = await open(file, 'r');
                try {
                    const expected = Buffer.alloc(bytes.length);
                    let read = 0;
                    while (read < expected.length) {
                        const result = await handle.read(
                            expected,
                            read,
                            expected.length - read,
                            offset + read,
                        );
                        if (result.bytesRead === 0) return false;
                        read += result.bytesRead;
                    }
                    return expected.equals(bytes);
                } finally {
                    await handle.close();
                }
            }
            await mkdir(path.dirname(file), { recursive: true });
            await writeFile(file, bytes, { flag: 'a' });
            if (!owners.has(file)) owners.set(file, origin);
            return true;
        } finally {
            if (pending.get(file) === released) pending.delete(file);
            unlock();
        }
    };
};
