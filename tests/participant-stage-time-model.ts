type Measurement = Readonly<{ name: string; milliseconds?: number }>;

export const measureContributionPreparationStage = (
    observations: readonly Measurement[],
) => {
    const recorded = new Map<string, number>();
    const names = new Set([
        'roster',
        'checkpoint',
        'roster-and-checkpoint',
        'body',
        'confirmation',
        'published-confirmation',
        'pending-delivery',
    ]);
    for (const observation of observations) {
        if (!names.has(observation.name) || recorded.has(observation.name))
            throw new Error('Unknown or duplicated stage measurement.');
        if (
            typeof observation.milliseconds !== 'number' ||
            !Number.isFinite(observation.milliseconds) ||
            observation.milliseconds < 0
        )
            throw new Error('A controller duration is missing or invalid.');
        recorded.set(observation.name, observation.milliseconds);
    }
    const combined = recorded.has('roster-and-checkpoint');
    if (combined && (recorded.has('roster') || recorded.has('checkpoint')))
        throw new Error('Coalesced work cannot also be counted separately.');
    const required = [
        ...(combined ? ['roster-and-checkpoint'] : ['roster', 'checkpoint']),
        'body',
        'confirmation',
        'published-confirmation',
    ];
    let activeMilliseconds = 0;
    for (const name of required) {
        const duration = recorded.get(name);
        if (duration === undefined)
            throw new Error(
                'Required same-stage work was not measured: ' + name,
            );
        activeMilliseconds += duration;
    }
    if (!Number.isFinite(activeMilliseconds))
        throw new Error('The summed duration is not finite.');
    return {
        activeMilliseconds,
        recoveryMilliseconds: recorded.get('pending-delivery') ?? 0,
    };
};
