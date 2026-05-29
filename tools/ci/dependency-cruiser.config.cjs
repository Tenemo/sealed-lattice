const path = require('node:path');

const workspaceRoot = path.resolve(__dirname, '..', '..');
const workspacePackageRoot = '^packages/[^/]+/';

module.exports = {
    forbidden: [
        {
            name: 'no-cycles',
            severity: 'error',
            from: {},
            to: {
                circular: true,
            },
        },
        {
            name: 'types-stays-foundational',
            severity: 'error',
            from: {
                path: '^packages/types/',
            },
            to: {
                path: '^packages/(crypto|protocol|sdk|wasm)/',
            },
        },
        {
            name: 'crypto-only-uses-types',
            severity: 'error',
            from: {
                path: '^packages/crypto/',
            },
            to: {
                path: '^packages/(protocol|sdk|wasm)/',
            },
        },
        {
            name: 'wasm-only-uses-types',
            severity: 'error',
            from: {
                path: '^packages/wasm/',
            },
            to: {
                path: '^packages/(crypto|protocol|sdk)/',
            },
        },
        {
            name: 'protocol-does-not-use-sdk-or-wasm',
            severity: 'error',
            from: {
                path: '^packages/protocol/',
            },
            to: {
                path: '^packages/(sdk|wasm)/',
            },
        },
        {
            name: 'no-deep-workspace-package-imports',
            severity: 'error',
            from: {
                path: workspacePackageRoot,
            },
            to: {
                path: workspacePackageRoot,
                dependencyTypes: ['npm-no-pkg'],
            },
        },
        {
            name: 'no-unresolved-imports',
            severity: 'error',
            from: {},
            to: {
                couldNotResolve: true,
            },
        },
    ],
    options: {
        combinedDependencies: true,
        doNotFollow: {
            path: 'node_modules',
        },
        exclude: {
            path: '(^|/)(dist|node_modules)(/|$)',
        },
        tsConfig: {
            fileName: path.join(workspaceRoot, 'tsconfig.tools.json'),
        },
    },
};
