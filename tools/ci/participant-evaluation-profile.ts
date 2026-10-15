import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import * as ts from 'typescript';

const measuredFunctions = {
    verifyCloseBarrier: 'close-verification',
    classifyBallot: 'ballot-classification',
    evaluate: 'encrypted-evaluation',
    retainEvaluation: 'target-persistence',
    commitTarget: 'target-persistence',
    restoreEvaluation: 'target-restoration',
    relayWaits: 'retrieval',
    openEvaluationStorage: 'working-storage',
    writeEvaluationStorage: 'working-storage',
    readStoredBlobs: 'working-storage',
    storedBytes: 'working-storage',
    evaluationCommand: 'evaluation-module',
    tryEvaluationCommand: 'evaluation-module',
} as const;

type EvaluationSpan = Readonly<{
    phase: string;
    started: number;
    finished: number;
}>;

export type EvaluationProfile = Readonly<{
    spans: readonly EvaluationSpan[];
    bookkeepingMilliseconds: number;
    targetDigests?: readonly string[];
    targetDigestMilliseconds?: number;
}>;

// Copied into the diagnostic worker only. Values and errors pass through
// unchanged; timers retain no arguments, return values or protocol bytes.
const evaluationTimerSource = `const evaluationTimer = (() => {
    const spans = [];
    const targetDigests = [];
    let targetDigestMilliseconds = 0;
    let bookkeepingMilliseconds = 0;
    const end = (phase, started) => {
        const finished = performance.now();
        if (spans.length === 200000) throw new Error('The evaluation diagnostic exceeded its span bound.');
        spans.push({phase, started, finished});
        bookkeepingMilliseconds += performance.now() - finished;
    };
    const asynchronous = (phase, operation) => async (...args) => {
        const started = performance.now();
        let result;
        try { result = await operation(...args); } finally { end(phase, started); }
        if (phase === 'encrypted-evaluation') {
            const digestStarted = performance.now();
            targetDigests.push(Array.from(new Uint8Array(await crypto.subtle.digest('SHA-512', result)), value => value.toString(16).padStart(2, '0')).join(''));
            targetDigestMilliseconds += performance.now() - digestStarted;
        }
        return result;
    };
    const synchronous = (phase, operation) => (...args) => {
        const started = performance.now();
        try { return operation(...args); } finally { end(phase, started); }
    };
    const postMessage = self.postMessage.bind(self);
    self.postMessage = message => {
        if (message.status !== undefined) postMessage({type: 'participant-evaluation-profile', profile: {spans, bookkeepingMilliseconds, targetDigests, targetDigestMilliseconds}});
        postMessage(message);
    };
    return {asynchronous, synchronous};
})();\n`;

export const instrumentEvaluation = (worker: Buffer, phases = true) => {
    const source = worker.toString('utf8');
    const parsed = ts.createSourceFile(
        'participant-worker.js',
        source,
        ts.ScriptTarget.Latest,
        true,
    );
    const replacements: { start: number; end: number; text: string }[] = [];
    for (const [name, phase] of Object.entries(measuredFunctions)) {
        if (!phases && name !== 'evaluate') continue;
        const matches: ts.ArrowFunction[] = [];
        const visit = (node: ts.Node) => {
            if (
                ts.isVariableDeclaration(node) &&
                ts.isIdentifier(node.name) &&
                node.name.text === name &&
                node.initializer !== undefined &&
                ts.isArrowFunction(node.initializer)
            )
                matches.push(node.initializer);
            ts.forEachChild(node, visit);
        };
        visit(parsed);
        assert.equal(
            matches.length,
            1,
            `Expected one evaluation diagnostic function: ${name}`,
        );
        const match = matches[0];
        const asynchronous = match.modifiers?.some(
            (modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword,
        );
        replacements.push({
            start: match.getStart(parsed),
            end: match.end,
            text:
                name === 'relayWaits'
                    ? `(...args) => evaluationTimer.asynchronous('retrieval', (${match.getText(parsed)})(...args))`
                    : `evaluationTimer.${asynchronous ? 'asynchronous' : 'synchronous'}(${JSON.stringify(phase)}, ${match.getText(parsed)})`,
        });
    }
    const signing: ts.CallExpression[] = [];
    const visitSigning = (node: ts.Node) => {
        if (
            ts.isCallExpression(node) &&
            ts.isIdentifier(node.expression) &&
            node.expression.text === 'finalityCommand' &&
            node.arguments[1]?.getText(parsed) === 'finalityOperation.signVote'
        )
            signing.push(node);
        ts.forEachChild(node, visitSigning);
    };
    visitSigning(parsed);
    assert.equal(
        signing.length,
        1,
        'Expected one original target-signing call.',
    );
    const signature = signing[0];
    if (phases)
        replacements.push({
            start: signature.getStart(parsed),
            end: signature.end,
            text: `evaluationTimer.synchronous('target-signing', () => ${signature.getText(parsed)})()`,
        });
    let patched = source;
    for (const replacement of replacements.sort(
        (left, right) => right.start - left.start,
    ))
        patched =
            patched.slice(0, replacement.start) +
            replacement.text +
            patched.slice(replacement.end);
    const bytes = Buffer.from(evaluationTimerSource + patched);
    return {
        worker: bytes,
        digest: createHash('sha512').update(bytes).digest('hex'),
    };
};

// Preserve the SDK's worker lifecycle, memory split, API and original
// protocol context. Only this diagnostic copy substitutes the worker text
// and routes its timing messages to the harness instead of the result path.
export const instrumentEvaluationSdk = (sdk: Buffer, worker: Buffer) => {
    const instrumented = instrumentEvaluation(worker);
    const source = sdk.toString('utf8');
    const parsed = ts.createSourceFile(
        'sdk.js',
        source,
        ts.ScriptTarget.Latest,
        true,
    );
    const literals: ts.StringLiteral[] = [];
    const resolutions: ts.ExpressionStatement[] = [];
    const visit = (node: ts.Node) => {
        if (ts.isStringLiteral(node) && node.text === worker.toString('utf8'))
            literals.push(node);
        if (
            ts.isExpressionStatement(node) &&
            ts.isCallExpression(node.expression) &&
            ts.isIdentifier(node.expression.expression) &&
            node.expression.expression.text === 'resolve' &&
            node.expression.arguments.length === 1 &&
            node.expression.arguments[0].getText(parsed) === 'event.data'
        )
            resolutions.push(node);
        ts.forEachChild(node, visit);
    };
    visit(parsed);
    assert.equal(
        literals.length,
        1,
        'Expected one SDK copy of the packaged worker.',
    );
    assert.equal(
        resolutions.length,
        1,
        'Expected one SDK worker-result boundary.',
    );
    let patched = source;
    const replacements = [
        {
            node: literals[0],
            text: JSON.stringify(instrumented.worker.toString('utf8')),
        },
        {
            node: resolutions[0],
            text: `if (event.data?.type === 'participant-evaluation-profile') { window.dispatchEvent(new CustomEvent('participant-evaluation-profile', { detail: event.data.profile })); return; }\n${resolutions[0].getText(parsed)}`,
        },
    ];
    for (const replacement of replacements.sort(
        (left, right) => right.node.pos - left.node.pos,
    ))
        patched =
            patched.slice(0, replacement.node.getStart(parsed)) +
            replacement.text +
            patched.slice(replacement.node.end);
    return { ...instrumented, sdk: Buffer.from(patched) };
};

// A sweep of interval endpoints counts parallel or nested work once. The
// inclusive totals are diagnostic views, not additive costs. The partition
// distinguishes overlapping I/O and module calls instead of subtracting
// durations that may overlap each other.
export const summarizeEvaluationProfile = (profile: EvaluationProfile) => {
    assert.ok(
        Number.isFinite(profile.bookkeepingMilliseconds) &&
            profile.bookkeepingMilliseconds >= 0,
    );
    const phases = new Set<string>([
        ...Object.values(measuredFunctions),
        'target-signing',
    ]);
    const endpoints: { time: number; phase: string; delta: number }[] = [];
    for (const span of profile.spans) {
        assert.ok(
            phases.has(span.phase) &&
                Number.isFinite(span.started) &&
                Number.isFinite(span.finished) &&
                span.finished >= span.started &&
                span.started >= 0,
        );
        endpoints.push(
            { time: span.started, phase: span.phase, delta: 1 },
            { time: span.finished, phase: span.phase, delta: -1 },
        );
    }
    endpoints.sort((left, right) => left.time - right.time);
    const active = new Map<string, number>();
    const inclusive: Record<string, number> = {};
    const partition: Record<string, number> = {};
    let previous = endpoints[0]?.time ?? 0;
    for (const endpoint of endpoints) {
        const elapsed = endpoint.time - previous;
        const running = [...active]
            .filter(([, count]) => count > 0)
            .map(([phase]) => phase);
        if (elapsed > 0 && running.length > 0) {
            for (const phase of running)
                inclusive[phase] = (inclusive[phase] ?? 0) + elapsed;
            const detailed = running.filter((phase) =>
                ['retrieval', 'working-storage', 'evaluation-module'].includes(
                    phase,
                ),
            );
            const primary =
                running
                    .filter((phase) => !detailed.includes(phase))
                    .sort()
                    .join(' + ') || 'unscoped';
            const key =
                primary +
                (detailed.length > 0
                    ? ' / ' + detailed.sort().join(' + ')
                    : '');
            partition[key] = (partition[key] ?? 0) + elapsed;
        }
        active.set(
            endpoint.phase,
            (active.get(endpoint.phase) ?? 0) + endpoint.delta,
        );
        previous = endpoint.time;
    }
    assert.ok([...active.values()].every((count) => count === 0));
    return {
        calls: profile.spans.length,
        targetDigests: profile.targetDigests ?? [],
        targetDigestMilliseconds: profile.targetDigestMilliseconds ?? 0,
        bookkeepingMilliseconds: profile.bookkeepingMilliseconds,
        inclusiveMilliseconds: inclusive,
        partitionMilliseconds: partition,
        measuredUnionMilliseconds: Object.values(partition).reduce(
            (sum, value) => sum + value,
            0,
        ),
    };
};
