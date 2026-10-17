import assert from 'node:assert/strict';

import * as ts from 'typescript';

type Checkpoint =
    | 'root-readback'
    | 'selection-readback'
    | 'proof-slot-store'
    | 'proof-finish'
    | 'proof-body-commit'
    | 'operation-module';

const statement = (source: string) =>
    ts.createSourceFile('checkpoint.js', source, ts.ScriptTarget.Latest, true)
        .statements[0];

const checkpoints = {
    'root-readback': {
        statement: statement('return { head, plaintext: reopened, manifest };'),
        description: 'one completed root readback',
    },
    'selection-readback': {
        statement: statement('await publication.finish();'),
        previous: statement(
            "await publication.addBytes('signature.bin', retained.signature);",
        ),
        description: 'one authenticated selection-readback continuation',
    },
    'proof-slot-store': {
        statement: statement(
            'await store({ offset: stored, length: used }, buffer.subarray(0, used));',
        ),
        description: 'one completed private proof-slot store',
    },
    'proof-finish': {
        statement: statement('const length = await writer.finish();'),
        next: statement(
            'header = signing(context, offerSigningOperation.bodyHeader, concatenate(unsigned16(state.position), unsigned64(BigInt(length))));',
        ),
        description: 'one completed contribution proof writer',
    },
    'proof-body-commit': {
        statement: statement(
            'await commitContribution(session, { state: { ...state, phase: contributionPhase.body, header, publicRecords: [...state.publicRecords, ...proof], privateRecords: [], seed: new Uint8Array() }, staged: true, clearCheckpoint: true });',
        ),
        description: 'one completed contribution body commit',
    },
    'operation-module': {
        statement: statement('await WebAssembly.compile(delivered.bytes);'),
        next: statement(
            'const evaluation = evaluatingOperations.has(command.operation);',
        ),
        description: 'one participant-operation module compilation',
    },
} as const;

const children = (node: ts.Node) => {
    const result: ts.Node[] = [];
    ts.forEachChild(node, (child) => {
        result.push(child);
    });
    return result;
};

// Compare syntax nodes, so whitespace, comments and string literals that
// merely contain checkpoint text cannot select an instrumentation site.
const sameSyntax = (left: ts.Node, right: ts.Node): boolean => {
    if (left.kind !== right.kind) return false;
    if (ts.isIdentifier(left) && ts.isIdentifier(right))
        return left.text === right.text;
    if (ts.isLiteralExpression(left) && ts.isLiteralExpression(right))
        return left.text === right.text;
    const first = children(left);
    const second = children(right);
    return (
        first.length === second.length &&
        first.every((child, index) => sameSyntax(child, second[index]))
    );
};

const adjacentStatement = (
    node: ts.Node,
    offset: number,
): ts.Statement | undefined => {
    let current = node;
    while (current.parent !== undefined && !ts.isBlock(current.parent))
        current = current.parent;
    if (current.parent === undefined) return undefined;
    const block = current.parent;
    const index = block.statements.findIndex((child) => child === current);
    return block.statements[index + offset];
};

// Only development tooling imports this module. It edits exactly one
// selected syntax location in the packaged worker and preserves every byte
// outside that location, including the independent outcome-verification path.
export const rewriteWorkerCheckpoint = (
    worker: Buffer,
    checkpoint: Checkpoint,
    replacement: (original: string) => string,
): Buffer => {
    const source = worker.toString('utf8');
    const parsed = ts.createSourceFile(
        'participant-worker.js',
        source,
        ts.ScriptTarget.Latest,
        true,
    );
    const selected = checkpoints[checkpoint];
    const matches: ts.Node[] = [];
    const visit = (node: ts.Node) => {
        const template =
            checkpoint === 'operation-module'
                ? (selected.statement as ts.ExpressionStatement).expression
                : selected.statement;
        if (sameSyntax(node, template)) {
            const next = adjacentStatement(node, 1);
            const previous = adjacentStatement(node, -1);
            if (
                (!('next' in selected) ||
                    (next !== undefined && sameSyntax(next, selected.next))) &&
                (!('previous' in selected) ||
                    (previous !== undefined &&
                        sameSyntax(previous, selected.previous)))
            )
                matches.push(node);
        }
        ts.forEachChild(node, visit);
    };
    visit(parsed);
    assert.equal(
        matches.length,
        1,
        'The worker must contain ' + selected.description + '.',
    );
    const match = matches[0];
    const start = match.getStart(parsed);
    return Buffer.from(
        source.slice(0, start) +
            replacement(source.slice(start, match.end)) +
            source.slice(match.end),
    );
};
