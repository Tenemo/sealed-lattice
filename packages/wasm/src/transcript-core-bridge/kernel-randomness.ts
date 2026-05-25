const createFreshRandomnessHex = (): string => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Proof generation requires Web Crypto getRandomValues for fresh prover randomness.',
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

export const componentProverRandomnessHexes = (
    componentProofInputs: readonly unknown[],
    suppliedRandomnessHexes: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> => {
    const randomnessHexes: Record<string, string> = {
        ...(suppliedRandomnessHexes ?? {}),
    };

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
