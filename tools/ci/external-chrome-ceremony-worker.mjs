const candidateModuleRoot = '/candidate/dist';
const { installPrivatePreparationWorker } = await import(
    `${candidateModuleRoot}/private-preparation-worker-runtime.js`
);

const boundary = new URL(globalThis.location.href).searchParams.get('boundary');

const stopAfter = (expectedBoundary) =>
    boundary === expectedBoundary
        ? async () => {
              globalThis.postMessage({
                  boundary: expectedBoundary,
                  kind: 'external-ceremony-crash-boundary',
              });
              await new Promise(() => {});
          }
        : undefined;

installPrivatePreparationWorker(globalThis, {
    afterDurableConsume: stopAfter('preparation-consume'),
    afterDurableSourceBind: stopAfter('source-bind'),
    afterDurableTallyGenerationInitialize: stopAfter(
        'tally-generation-initialize',
    ),
    afterDurableTallyChunkPersist: stopAfter('tally-chunk-persist'),
    afterDurableTallyActivationPublish: stopAfter('tally-activation-publish'),
    afterDurableTallyEvaluationInitialize: stopAfter(
        'tally-evaluation-initialize',
    ),
    afterDurableTallyEvaluationStep: stopAfter('tally-evaluation-step'),
    afterDurableTallyTerminalPersist: stopAfter('tally-terminal-persist'),
    persistentStorageRequired: true,
    unpinnedKernelAllowed: false,
});
