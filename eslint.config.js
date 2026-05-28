import eslintJs from '@eslint/js';
import typescriptEslintPlugin from '@typescript-eslint/eslint-plugin';
import * as typescriptParser from '@typescript-eslint/parser';
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript';
import {
    createNodeResolver,
    flatConfigs as importFlatConfigs,
} from 'eslint-plugin-import-x';
import errorOnlyPlugin from 'eslint-plugin-only-error';
import prettierPluginRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';

const OFF = 0;
const ERROR = 2;

const projectPaths = [
    './tsconfig.tools.json',
    './packages/*/tsconfig.json',
    './docs/tsconfig.json',
];

/** @type {import('eslint').Linter.FlatConfig[]} */
const config = [
    importFlatConfigs.errors,
    importFlatConfigs.warnings,
    importFlatConfigs.typescript,
    ...typescriptEslintPlugin.configs['flat/recommended-type-checked'],
    ...typescriptEslintPlugin.configs['flat/stylistic-type-checked'],
    prettierPluginRecommended,
    {
        files: ['**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx', '**/*.mjs'],
        rules: {
            ...eslintJs.configs.recommended.rules,
            'arrow-parens': [ERROR, 'always', { requireForBlockBody: false }],
            'no-redeclare': OFF,
            'no-restricted-exports': OFF,
            'no-restricted-properties': [
                ERROR,
                {
                    object: 'Math',
                    property: 'random',
                    message:
                        'Use the project crypto-backed randomness helpers instead.',
                },
            ],
            'no-shadow': OFF,
            'no-undef': OFF,
            'no-unused-vars': OFF,
            '@typescript-eslint/no-use-before-define': ERROR,
            '@typescript-eslint/no-shadow': ERROR,
            '@typescript-eslint/explicit-module-boundary-types': ERROR,
            '@typescript-eslint/unbound-method': ERROR,
            '@typescript-eslint/explicit-function-return-type': [
                ERROR,
                {
                    allowExpressions: true,
                    allowTypedFunctionExpressions: true,
                },
            ],
            '@typescript-eslint/consistent-type-definitions': ['error', 'type'],
            'prettier/prettier': [
                ERROR,
                {
                    useTabs: false,
                    semi: true,
                    singleQuote: true,
                    jsxSingleQuote: false,
                    trailingComma: 'all',
                    arrowParens: 'always',
                    endOfLine: 'lf',
                },
            ],
            'import-x/no-extraneous-dependencies': [
                ERROR,
                { devDependencies: true },
            ],
            'import-x/prefer-default-export': OFF,
            'import-x/extensions': [
                ERROR,
                'ignorePackages',
                {
                    js: 'never',
                    jsx: 'never',
                    ts: 'never',
                    tsx: 'never',
                },
            ],
            'import-x/order': [
                ERROR,
                {
                    'newlines-between': 'always',
                    alphabetize: { order: 'asc', caseInsensitive: true },
                    pathGroupsExcludedImportTypes: ['builtin'],
                },
            ],
        },
        plugins: {
            'only-error': errorOnlyPlugin,
        },
        settings: {
            react: {
                version: 'detect',
            },
            'import-x/internal-regex':
                '^#(?:packages|test-vectors|tests|tools)(?:/|$)',
            'import-x/resolver-next': [
                createTypeScriptImportResolver({
                    alwaysTryTypes: true,
                    noWarnOnMultipleProjects: true,
                    project: projectPaths,
                }),
                createNodeResolver({
                    extensions: [
                        '.ts',
                        '.tsx',
                        '.d.ts',
                        '.js',
                        '.jsx',
                        '.json',
                        '.node',
                    ],
                    extensionAlias: {
                        '.js': ['.ts', '.tsx', '.d.ts', '.js'],
                        '.jsx': ['.tsx', '.d.ts', '.jsx'],
                        '.cjs': ['.cts', '.d.cts', '.cjs'],
                        '.mjs': ['.mts', '.d.mts', '.mjs'],
                    },
                    conditionNames: [
                        'types',
                        'import',
                        'esm2020',
                        'es2020',
                        'es2015',
                        'require',
                        'node',
                        'node-addons',
                        'browser',
                        'default',
                    ],
                    mainFields: [
                        'types',
                        'typings',
                        'fesm2020',
                        'fesm2015',
                        'esm2020',
                        'es2020',
                        'module',
                        'jsnext:main',
                        'main',
                    ],
                }),
            ],
        },
        linterOptions: {
            reportUnusedDisableDirectives: true,
        },
        languageOptions: {
            parser: typescriptParser,
            parserOptions: {
                sourceType: 'module',
                ecmaFeatures: {
                    jsx: true,
                },
                project: projectPaths,
                noWarnOnMultipleProjects: true,
                ecmaVersion: 2021,
            },
            globals: {
                ...globals.browser,
                ...globals.node,
                ...globals.es2021,
                ...globals.commonjs,
            },
        },
    },
    {
        files: ['docs/src/content.config.ts'],
        rules: {
            'import-x/no-unresolved': OFF,
        },
    },
    {
        files: ['**/*.cjs', '**/*.cts', '**/*.mts'],
        languageOptions: {
            parser: typescriptParser,
            parserOptions: {
                sourceType: 'module',
                ecmaFeatures: {
                    jsx: true,
                },
                project: projectPaths,
                noWarnOnMultipleProjects: true,
                ecmaVersion: 2021,
            },
            globals: {
                ...globals.node,
                ...globals.es2021,
                ...globals.commonjs,
            },
        },
    },
    {
        files: ['**/*.cjs', '**/*.js', '**/*.mjs', '**/*.mts'],
        rules: {
            '@typescript-eslint/no-unsafe-assignment': OFF,
            '@typescript-eslint/no-unsafe-member-access': OFF,
            '@typescript-eslint/no-unsafe-call': OFF,
        },
    },
    {
        files: ['packages/*/tests/**/*.ts', 'tests/**/*.ts'],
        languageOptions: {
            parserOptions: {
                project: './tsconfig.tools.json',
            },
        },
        rules: {
            'import-x/no-extraneous-dependencies': [
                ERROR,
                {
                    devDependencies: true,
                    // Vitest resolves this package name to the built public SDK entry point for public-package tests.
                    whitelist: ['sealed-lattice'],
                },
            ],
        },
    },
    {
        ignores: [
            '.tmp',
            '.tmp/**',
            '.tmp-*',
            '.tmp-*/**',
            '.tmp_*',
            '.tmp_*/**',
            '.tmp.*',
            '.tmp.*/**',
            'temp',
            'temp/**',
            'temp-*',
            'temp-*/**',
            'temp.*',
            'temp.*/**',
            'tmp',
            'tmp/**',
            'tmp-*',
            'tmp-*/**',
            'tmp.*',
            'tmp.*/**',
            'node_modules',
            'node_modules/**',
            'dist',
            'dist/**',
            '**/dist',
            '**/dist/**',
            'coverage',
            'coverage/**',
            'target',
            'target/**',
            'docs/.astro',
            'docs/.astro/**',
            'docs/dist',
            'docs/dist/**',
        ],
    },
    {
        files: ['tools/ci/*.mjs'],
        languageOptions: {
            parserOptions: {
                project: './tsconfig.tools.json',
            },
        },
        rules: {
            '@typescript-eslint/explicit-module-boundary-types': OFF,
            '@typescript-eslint/explicit-function-return-type': OFF,
            '@typescript-eslint/no-unsafe-argument': OFF,
        },
    },
    {
        files: ['**/*.cjs'],
        rules: {
            '@typescript-eslint/no-require-imports': OFF,
            '@typescript-eslint/no-unsafe-assignment': OFF,
            '@typescript-eslint/no-unsafe-call': OFF,
            '@typescript-eslint/no-unsafe-member-access': OFF,
        },
    },
];

export default config;
