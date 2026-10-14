import eslintJs from '@eslint/js';
import * as vitestPluginModule from '@vitest/eslint-plugin';
import { defineConfig, globalIgnores } from 'eslint/config';
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript';
import { flatConfigs as importFlatConfigs } from 'eslint-plugin-import-x';
import prettierPluginRecommended from 'eslint-plugin-prettier/recommended';
import * as unusedImportsPluginModule from 'eslint-plugin-unused-imports';
import globals from 'globals';
import {
    configs as typescriptEslintConfigs,
    parser as typescriptParser,
} from 'typescript-eslint';

const sourceFiles = ['**/*.{js,mjs,ts}'];
const javaScriptFiles = ['**/*.{js,mjs}'];
const testFiles = ['packages/*/tests/**/*.ts', 'tests/node/**/*.ts'];
const toolFiles = ['tools/**/*.{ts,mjs}', '*.config.{ts,js}'];

const projectPaths = ['./tsconfig.tools.json', './packages/*/tsconfig.json'];

const unusedImportsPlugin = unusedImportsPluginModule.default;
const vitestPlugin = vitestPluginModule.default;

const parserOptions = {
    sourceType: 'module',
    project: projectPaths,
    noWarnOnMultipleProjects: true,
    ecmaVersion: 2021,
};

const importResolverSettings = {
    'import-x/internal-regex': '^#(?:packages|tests|tools)(?:/|$)',
    'import-x/resolver-next': [
        createTypeScriptImportResolver({
            alwaysTryTypes: true,
            noWarnOnMultipleProjects: true,
            project: projectPaths,
        }),
    ],
};

const packageSourceImportPatterns = [
    {
        group: ['#packages/*', '#tests/*', '#tools/*'],
        message:
            'Published package source must not depend on repository-private aliases.',
    },
];

export default defineConfig(
    globalIgnores([
        'logs/**',
        'temp/**',
        'reference-projects/**',
        '**/dist/**',
        '**/target/**',
    ]),
    {
        linterOptions: {
            reportUnusedDisableDirectives: true,
        },
    },
    importFlatConfigs.errors,
    importFlatConfigs.warnings,
    importFlatConfigs.typescript,
    ...typescriptEslintConfigs.recommendedTypeChecked,
    prettierPluginRecommended,
    {
        files: sourceFiles,
        languageOptions: {
            parser: typescriptParser,
            parserOptions,
            globals: {
                ...globals.browser,
                ...globals.es2021,
            },
        },
        plugins: {
            'unused-imports': unusedImportsPlugin,
        },
        settings: importResolverSettings,
        rules: {
            ...eslintJs.configs.recommended.rules,
            'no-redeclare': 'off',
            'no-restricted-properties': [
                'error',
                {
                    object: 'Math',
                    property: 'random',
                    message:
                        'Use the project crypto-backed randomness helpers instead.',
                },
            ],
            'no-undef': 'off',
            'no-unused-vars': 'off',
            '@typescript-eslint/no-unused-vars': 'off',
            '@typescript-eslint/no-shadow': 'error',
            '@typescript-eslint/unbound-method': 'error',
            'unused-imports/no-unused-imports': 'error',
            'unused-imports/no-unused-vars': [
                'error',
                {
                    vars: 'all',
                    varsIgnorePattern: '^_',
                    args: 'after-used',
                    argsIgnorePattern: '^_',
                },
            ],
            'prettier/prettier': 'error',
            'import-x/no-extraneous-dependencies': [
                'error',
                { devDependencies: true },
            ],
            'import-x/no-duplicates': 'error',
            'import-x/extensions': [
                'error',
                'ignorePackages',
                {
                    js: 'never',
                    mjs: 'never',
                    ts: 'never',
                },
            ],
            'import-x/order': [
                'error',
                {
                    'newlines-between': 'always',
                    alphabetize: { order: 'asc', caseInsensitive: true },
                    pathGroupsExcludedImportTypes: ['builtin'],
                },
            ],
        },
    },
    {
        files: ['packages/*/src/**/*.ts'],
        rules: {
            'import-x/no-cycle': ['error', { ignoreExternal: true }],
            'import-x/no-relative-packages': 'error',
            'no-restricted-imports': [
                'error',
                { patterns: packageSourceImportPatterns },
            ],
        },
    },
    {
        files: toolFiles,
        languageOptions: {
            parserOptions: {
                project: './tsconfig.tools.json',
            },
            globals: {
                ...globals.node,
            },
        },
    },
    {
        files: javaScriptFiles,
        rules: {
            '@typescript-eslint/no-unsafe-assignment': 'off',
            '@typescript-eslint/no-unsafe-member-access': 'off',
            '@typescript-eslint/no-unsafe-call': 'off',
        },
    },
    {
        files: testFiles,
        languageOptions: {
            parserOptions: {
                project: './tsconfig.tools.json',
            },
            globals: {
                ...vitestPlugin.environments.env.globals,
            },
        },
        plugins: {
            vitest: vitestPlugin,
        },
        rules: {
            ...vitestPlugin.configs.recommended.rules,
            'vitest/expect-expect': [
                'error',
                {
                    assertFunctionNames: ['expect', 'assert', 'expect*'],
                },
            ],
            'vitest/valid-expect': ['error', { minArgs: 1, maxArgs: 2 }],
            'vitest/no-focused-tests': 'error',
            'vitest/no-disabled-tests': 'error',
        },
    },
    {
        files: ['tests/**/*.ts'],
        ignores: ['tests/node/**'],
        rules: {
            'no-restricted-imports': [
                'error',
                {
                    patterns: [
                        {
                            regex: '^(?:#tests/node/|(?:\\.\\.?/)+node/)',
                            message:
                                'A model must not depend on the tests that check it.',
                        },
                    ],
                },
            ],
        },
    },
    {
        files: ['tests/node/protocol/reference/**/*.ts'],
        rules: {
            'no-restricted-imports': [
                'error',
                {
                    patterns: [
                        {
                            regex: '^(?!node:|#tests/node/rust-source\\.js$)',
                            message:
                                'A test reference imports only Node built-ins and the Rust source reader.',
                        },
                    ],
                },
            ],
        },
    },
    {
        files: ['packages/sdk/tests/node/public-api.test.ts'],
        rules: {
            'import-x/extensions': [
                'error',
                'ignorePackages',
                {
                    js: 'always',
                    mjs: 'always',
                    ts: 'never',
                },
            ],
        },
    },
);
