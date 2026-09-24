interface ReleaseRecordState {
    readonly journalKeys: readonly Uint8Array[];
    readonly bodyKeys: readonly Uint8Array[];
    readonly bodyLength: number;
}

interface ReleaseRecordConfiguration {
    readonly recordBytes: number;
    readonly totalRandomBytes: number;
}

interface ReleaseRecordReader {
    count(): Promise<number>;
    read(
        kind: number,
        index: number,
        key: Uint8Array,
        length: number,
    ): Promise<Uint8Array>;
}

// The owning record reader authenticates each ciphertext. This check consumes
// no protocol authority and must also run before unavailable public inputs can
// mask the loss of required local release state.
export async function verifyReleaseRecords(
    state: ReleaseRecordState | undefined,
    configuration: ReleaseRecordConfiguration,
    records: ReleaseRecordReader,
): Promise<void> {
    const count = await records.count();
    if (
        count !==
        (state?.journalKeys.length ?? 0) + (state?.bodyKeys.length ?? 0)
    )
        throw new Error('Release record inventory changed.');
    if (!state) return;
    for (const [kind, keys] of [
        [0, state.journalKeys],
        [1, state.bodyKeys],
    ] as const) {
        const total =
            kind === 0 ? configuration.totalRandomBytes : state.bodyLength;
        for (let index = 0; index < keys.length; index++) {
            const length = Math.min(
                configuration.recordBytes,
                total - index * configuration.recordBytes,
            );
            const bytes = await records.read(kind, index, keys[index], length);
            bytes.fill(0);
        }
    }
}
