interface ReleaseDelivery {
    readonly envelope: Uint8Array;
    readonly bodyRecordCount: number;
    readonly readBody: (index: number) => Promise<Uint8Array>;
    readonly inspect: () => Promise<void>;
    readonly send: (
        kind: 'envelope' | 'body',
        offset: number,
        bytes: Uint8Array,
    ) => Promise<void>;
}

// The caller supplies an already authorized completed message. Local inspection
// must succeed after each transfer before another transfer can start.
export async function publishReleaseRecords({
    envelope,
    bodyRecordCount,
    readBody,
    inspect,
    send,
}: ReleaseDelivery): Promise<void> {
    await inspect();
    try {
        await send('envelope', 0, envelope);
    } finally {
        await inspect();
    }
    let offset = 0;
    for (let index = 0; index < bodyRecordCount; index++) {
        const bytes = await readBody(index);
        try {
            await send('body', offset, bytes);
        } finally {
            bytes.fill(0);
            await inspect();
        }
        offset += bytes.length;
    }
}
