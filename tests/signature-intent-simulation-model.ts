type Message = Readonly<{ key: string; context: string; body: string }>;
type Intent = {
    message: Message;
    volatileResponse?: string;
    completedResponse?: string;
    lost: boolean;
};

// Abstract deterministic signing inputs, not a signature primitive. The real
// signer and its oracle use the same fixed zero signing input from FIPS 204.
const response = (message: Message): string =>
    JSON.stringify([message.key, message.context, message.body]);

export const createSignatureIntentSimulation = (
    mode: 'deterministic' | 'cached-oracle',
) => {
    const intents = new Map<string, Intent>();
    const oracleCache = new Map<string, string>();
    let signingEvaluations = 0;
    let oracleQueries = 0;
    const begin = (identity: string, message: Message): void => {
        if (!identity || intents.has(identity))
            throw new Error('Signing intent already consumed.');
        intents.set(identity, {
            message: { ...message },
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
        if (mode === 'deterministic') {
            value = response(intent.message);
        } else {
            const cached = oracleCache.get(identity);
            if (cached !== undefined) value = cached;
            else {
                oracleQueries++;
                value = response(intent.message);
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
        intent.volatileResponse = undefined;
    };
    const interrupt = (identity: string): void => {
        retained(identity).volatileResponse = undefined;
    };
    const loseRequiredState = (identity: string): void => {
        const intent = retained(identity);
        intent.lost = true;
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
            signingEvaluations,
            oracleQueries,
        }),
    };
};
