type Message = Readonly<{ key: string; context: string; body: string }>;
type Intent = {
    message: Message;
    coins?: number;
    volatileResponse?: string;
    completedResponse?: string;
    lost: boolean;
};

// This exposes an abstract deterministic function of signing inputs, not a
// cryptographic signature. Equality of the finite input distributions is
// preserved by deterministic ML-DSA signing. The reduction does not see coins
// chosen inside its standard signing oracle.
const response = (message: Message, coins: number): string =>
    JSON.stringify([message.key, message.context, message.body, coins]);

export const createSignatureIntentSimulation = (
    mode: 'retained-coins' | 'cached-oracle',
    randomness: readonly number[],
) => {
    const intents = new Map<string, Intent>();
    const oracleCache = new Map<string, string>();
    let randomIndex = 0;
    let signingEvaluations = 0;
    let oracleQueries = 0;
    const random = (): number => {
        const value = randomness[randomIndex++];
        if (value === undefined) throw new Error('Model randomness exhausted.');
        return value;
    };
    const begin = (identity: string, message: Message): void => {
        if (!identity || intents.has(identity))
            throw new Error('Signing intent already consumed.');
        intents.set(identity, {
            message: { ...message },
            coins: mode === 'retained-coins' ? random() : undefined,
            lost: false,
        });
    };
    const retained = (identity: string): Intent => {
        const intent = intents.get(identity);
        if (!intent || intent.lost)
            throw new Error('Required signing state unavailable.');
        return intent;
    };
    const evaluate = (identity: string, message: Message): string => {
        const intent = retained(identity);
        if (
            intent.message.key !== message.key ||
            intent.message.context !== message.context ||
            intent.message.body !== message.body
        )
            throw new Error('Signing target changed.');
        if (intent.completedResponse !== undefined)
            return intent.completedResponse;
        signingEvaluations++;
        let value: string;
        if (mode === 'retained-coins') {
            if (intent.coins === undefined)
                throw new Error('Signing coins unavailable.');
            value = response(intent.message, intent.coins);
        } else {
            const cached = oracleCache.get(identity);
            if (cached !== undefined) value = cached;
            else {
                oracleQueries++;
                value = response(intent.message, random());
                oracleCache.set(identity, value);
            }
        }
        intent.volatileResponse = value;
        return value;
    };
    const commit = (identity: string): void => {
        const intent = retained(identity);
        if (intent.volatileResponse === undefined)
            throw new Error('No evaluated response to retain.');
        intent.completedResponse = intent.volatileResponse;
        intent.coins = undefined;
        intent.volatileResponse = undefined;
    };
    const interrupt = (identity: string): void => {
        retained(identity).volatileResponse = undefined;
    };
    const loseRequiredState = (identity: string): void => {
        const intent = retained(identity);
        intent.lost = true;
        intent.coins = undefined;
        intent.volatileResponse = undefined;
        intent.completedResponse = undefined;
    };
    return {
        begin,
        evaluate,
        commit,
        interrupt,
        loseRequiredState,
        counts: () => ({
            randomDraws: randomIndex,
            signingEvaluations,
            oracleQueries,
        }),
    };
};

export const signatureIntentJointDistribution = (
    mode: 'retained-coins' | 'cached-oracle',
) => {
    const distribution = new Map<string, number>();
    const message = {
        key: 'original-credential',
        context: 'ballot',
        body: 'fixed-envelope',
    };
    for (let first = 0; first < 4; first++)
        for (let second = 0; second < 4; second++) {
            const model = createSignatureIntentSimulation(mode, [
                first,
                second,
            ]);
            model.begin('intent-a', message);
            model.begin('intent-b', message);
            // Reverse evaluation order: lazy oracle coins cannot be equated
            // pathwise to the earlier chronological intent-creation stream.
            const initial = model.evaluate('intent-b', message);
            model.interrupt('intent-b');
            const repeated = model.evaluate('intent-b', message);
            model.commit('intent-b');
            const other = model.evaluate('intent-a', message);
            const key = JSON.stringify([initial, repeated, other]);
            distribution.set(key, (distribution.get(key) ?? 0) + 1);
        }
    return [...distribution].sort(([left], [right]) =>
        left.localeCompare(right),
    );
};
