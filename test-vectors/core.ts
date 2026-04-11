export type TextVectorInput = {
    kind: 'text';
    value: string;
};

export type HexVectorInput = {
    kind: 'hex';
    value: string;
};

export type RepeatTextVectorInput = {
    count: number;
    kind: 'repeat-text';
    value: string;
};

export type CoreVectorInput =
    | TextVectorInput
    | HexVectorInput
    | RepeatTextVectorInput;

export type CoreVectorDefinition = {
    id: string;
    input: CoreVectorInput;
};

export type CoreVector = CoreVectorDefinition & {
    expected: string;
};

export const coreVectorDefinitions = [
    {
        id: 'empty-string',
        input: {
            kind: 'text',
            value: '',
        },
    },
    {
        id: 'ascii-text',
        input: {
            kind: 'text',
            value: 'sealed-lattice phase one',
        },
    },
    {
        id: 'unicode-text',
        input: {
            kind: 'text',
            value: 'za\u017c\u00f3\u0142\u0107 g\u0119\u015bl\u0105 ja\u017a\u0144',
        },
    },
    {
        id: 'raw-bytes',
        input: {
            kind: 'hex',
            value: '00ff1020aabbccdd',
        },
    },
    {
        id: 'repeated-text',
        input: {
            kind: 'repeat-text',
            value: 'lattice-',
            count: 128,
        },
    },
] as const satisfies readonly CoreVectorDefinition[];

export const expandCoreVectorInput = (
    input: CoreVectorInput,
): string | Uint8Array => {
    switch (input.kind) {
        case 'text':
            return input.value;
        case 'hex':
            return Uint8Array.from(
                input.value
                    .match(/.{1,2}/g)
                    ?.map((chunk) => Number.parseInt(chunk, 16)) ?? [],
            );
        case 'repeat-text':
            return input.value.repeat(input.count);
    }
};
