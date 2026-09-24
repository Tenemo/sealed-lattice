export type WorkflowCost = Readonly<{
    operation: string;
    stage: string;
    milliseconds: number | null;
}>;

const requireDuration = (value: number): void => {
    if (!Number.isFinite(value) || value < 0)
        throw new Error('Invalid workflow duration.');
};

// Unknown work is neither free nor evidence that a workflow meets its limit.
export const assessWorkflowCost = (
    costs: readonly WorkflowCost[],
    participantLimitMilliseconds: number,
    visitLimitMilliseconds: number,
) => {
    requireDuration(participantLimitMilliseconds);
    requireDuration(visitLimitMilliseconds);
    if (costs.length === 0) throw new Error('No workflow operations supplied.');
    const operations = new Set<string>();
    const stages = new Map<
        string,
        { measuredMilliseconds: number; unmeasuredOperations: string[] }
    >();
    for (const cost of costs) {
        if (!cost.operation || !cost.stage || operations.has(cost.operation))
            throw new Error('Missing or duplicated workflow operation.');
        operations.add(cost.operation);
        const stage = stages.get(cost.stage) ?? {
            measuredMilliseconds: 0,
            unmeasuredOperations: [],
        };
        if (cost.milliseconds === null)
            stage.unmeasuredOperations.push(cost.operation);
        else {
            requireDuration(cost.milliseconds);
            stage.measuredMilliseconds += cost.milliseconds;
            requireDuration(stage.measuredMilliseconds);
        }
        stages.set(cost.stage, stage);
    }
    const measuredMilliseconds = [...stages.values()].reduce(
        (sum, stage) => sum + stage.measuredMilliseconds,
        0,
    );
    requireDuration(measuredMilliseconds);
    const unmeasuredOperations = costs
        .filter((cost) => cost.milliseconds === null)
        .map((cost) => cost.operation);
    const minimumRequiredSavingMilliseconds = Math.max(
        0,
        measuredMilliseconds - participantLimitMilliseconds,
    );
    return {
        measuredMilliseconds,
        unmeasuredOperations,
        totalMilliseconds:
            unmeasuredOperations.length === 0 ? measuredMilliseconds : null,
        requiredSavingMilliseconds:
            unmeasuredOperations.length === 0
                ? minimumRequiredSavingMilliseconds
                : null,
        minimumRequiredSavingMilliseconds,
        stages: [...stages].map(([stage, value]) => ({
            stage,
            ...value,
            exceedsVisitLimit:
                value.measuredMilliseconds > visitLimitMilliseconds,
            complete: value.unmeasuredOperations.length === 0,
        })),
    };
};
