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
const testFiles = ['packages/*/tests/**/*.ts', 'tests/**/*.ts'];
const toolFiles = ['tools/**/*.ts', '*.config.{ts,js}'];

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
    {
        group: [
            '@sealed-lattice/*/*',
            '!@sealed-lattice/wasm/published-sdk',
            'sealed-lattice/*',
        ],
        message:
            'Workspace packages must import another package through its public entry point.',
    },
];

export default defineConfig(
    globalIgnores([
        '.tmp*/**',
        'temp/**',
        'node_modules/**',
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
            'no-restricted-exports': 'off',
            'no-restricted-properties': [
                'error',
                {
                    object: 'Math',
                    property: 'random',
                    message:
                        'Use the project crypto-backed randomness helpers instead.',
                },
            ],
            'no-shadow': 'off',
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
            'prettier/prettier': [
                'error',
                {
                    useTabs: false,
                    semi: true,
                    singleQuote: true,
                    trailingComma: 'all',
                    arrowParens: 'always',
                    endOfLine: 'lf',
                },
            ],
            'import-x/no-extraneous-dependencies': [
                'error',
                { devDependencies: true },
            ],
            'import-x/no-duplicates': 'error',
            'import-x/prefer-default-export': 'off',
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
            'import-x/no-relative-packages': 'error',
            'no-restricted-imports': [
                'error',
                { patterns: packageSourceImportPatterns },
            ],
        },
    },
    {
        files: ['packages/wasm/src/**/*.ts'],
        rules: {
            'no-restricted-imports': [
                'error',
                {
                    paths: ['sealed-lattice'],
                    patterns: packageSourceImportPatterns,
                },
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
        settings: {
            vitest: {
                typecheck: true,
            },
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
);
