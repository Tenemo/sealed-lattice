const preferredVisitCount = 5;
const maximumVisitCount = 10;

type VisitStage = Readonly<{
    id: string;
    dependsOn: readonly string[];
}>;

const successfulResultStages: readonly VisitStage[] = [
    { id: 'roster-confirmation-and-seed-commitment', dependsOn: [] },
    {
        id: 'seed-opening',
        dependsOn: ['roster-confirmation-and-seed-commitment'],
    },
    { id: 'setup-contribution', dependsOn: ['seed-opening'] },
    {
        id: 'setup-receipt-and-ballot',
        dependsOn: ['setup-contribution'],
    },
    { id: 'ballot-echo', dependsOn: ['setup-receipt-and-ballot'] },
    { id: 'ballot-ready', dependsOn: ['ballot-echo'] },
    { id: 'close-log', dependsOn: ['ballot-ready'] },
    { id: 'target-signature', dependsOn: ['close-log'] },
    { id: 'release-share', dependsOn: ['target-signature'] },
    { id: 'terminal-retrieval', dependsOn: ['release-share'] },
];

const noResultStages: readonly VisitStage[] = successfulResultStages
    .filter(({ id }) => id !== 'release-share')
    .map((stage) =>
        stage.id === 'terminal-retrieval'
            ? { ...stage, dependsOn: ['target-signature'] }
            : stage,
    );

const longestDependencyChain = (stages: readonly VisitStage[]): number => {
    const byId = new Map(stages.map((stage) => [stage.id, stage]));
    const memo = new Map<string, number>();
    const active = new Set<string>();

    const visit = (id: string): number => {
        const cached = memo.get(id);
        if (cached !== undefined) return cached;
        if (active.has(id))
            throw new Error('The visit graph contains a cycle.');
        const stage = byId.get(id);
        if (stage === undefined) {
            throw new Error(`The visit dependency ${id} is absent.`);
        }
        active.add(id);
        const depth =
            1 +
            Math.max(
                0,
                ...stage.dependsOn.map((dependency) => visit(dependency)),
            );
        active.delete(id);
        memo.set(id, depth);
        return depth;
    };

    return Math.max(...stages.map(({ id }) => visit(id)));
};

export type ParticipantVisitDependencyCensus = Readonly<{
    maximumPermittedVisitCount: number;
    noResultVisitCount: number;
    preferredVisitCount: number;
    successfulResultVisitCount: number;
    successfulResultStageCount: number;
    withinMaximumVisitCount: boolean;
    withinPreferredVisitCount: boolean;
}>;

export const compileParticipantVisitDependencyCensus =
    (): ParticipantVisitDependencyCensus => {
        const successfulResultVisitCount = longestDependencyChain(
            successfulResultStages,
        );
        const noResultVisitCount = longestDependencyChain(noResultStages);
        return {
            maximumPermittedVisitCount: maximumVisitCount,
            noResultVisitCount,
            preferredVisitCount,
            successfulResultVisitCount,
            successfulResultStageCount: successfulResultStages.length,
            withinMaximumVisitCount:
                successfulResultVisitCount <= maximumVisitCount,
            withinPreferredVisitCount:
                successfulResultVisitCount <= preferredVisitCount,
        };
    };
