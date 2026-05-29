const createFreshRandomnessHex = (): string => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Proof generation requires Web Crypto getRandomValues for fresh randomness.',
        );
    }
    const randomBytes = new Uint8Array(32);
    cryptoProvider.getRandomValues(randomBytes);

    return Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');
};

export const suppliedOrFreshRandomnessHex = (
    value: string | undefined,
): string => value ?? createFreshRandomnessHex();

export type BridgeRandomnessSource =
    | 'fresh-csprng'
    | 'development-deterministic-fixture';

type SuppliedOrFreshBridgeRandomness = {
    readonly randomnessHex: string;
    readonly randomnessSource: BridgeRandomnessSource;
};

export const suppliedOrFreshBridgeRandomness = (
    value: string | undefined,
    developmentRandomnessOverrideAcknowledged: boolean | undefined,
): SuppliedOrFreshBridgeRandomness => {
    if (value !== undefined) {
        if (developmentRandomnessOverrideAcknowledged !== true) {
            throw new RangeError(
                'Caller-supplied aggregate bridge randomness requires developmentRandomnessOverrideAcknowledged.',
            );
        }

        return {
            randomnessHex: value,
            randomnessSource: 'development-deterministic-fixture',
        };
    }

    return {
        randomnessHex: createFreshRandomnessHex(),
        randomnessSource: 'fresh-csprng',
    };
};

export const componentProverRandomnessHexes = (
    componentProofInputs: readonly unknown[],
    suppliedRandomnessHexes: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> => {
    const randomnessHexes: Record<string, string> = Object.create(
        null,
    ) as Record<string, string>;
    for (const [componentId, randomnessHex] of Object.entries(
        suppliedRandomnessHexes ?? {},
    )) {
        randomnessHexes[componentId] = randomnessHex;
    }

    for (const componentProofInput of componentProofInputs) {
        if (
            typeof componentProofInput === 'object' &&
            componentProofInput !== null &&
            'componentId' in componentProofInput
        ) {
            const componentId = (
                componentProofInput as { readonly componentId: unknown }
            ).componentId;
            if (
                typeof componentId === 'string' &&
                randomnessHexes[componentId] === undefined
            ) {
                randomnessHexes[componentId] = createFreshRandomnessHex();
            }
        }
    }

    return randomnessHexes;
};
