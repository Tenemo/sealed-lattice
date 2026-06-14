import eslintJs from '@eslint/js';
import * as vitestPluginModule from '@vitest/eslint-plugin';
import { defineConfig, globalIgnores } from 'eslint/config';
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript';
import {
    createNodeResolver,
    flatConfigs as importFlatConfigs,
} from 'eslint-plugin-import-x';
import prettierPluginRecommended from 'eslint-plugin-prettier/recommended';
import * as unusedImportsPluginModule from 'eslint-plugin-unused-imports';
import globals from 'globals';
import {
    configs as typescriptEslintConfigs,
    parser as typescriptParser,
} from 'typescript-eslint';

const OFF = 0;
const ERROR = 2;

const sourceFiles = ['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}'];
const typeScriptFiles = ['**/*.{ts,tsx,mts,cts}'];
const javaScriptFiles = ['**/*.{js,jsx,mjs,cjs}'];
const testFiles = ['packages/*/tests/**/*.{ts,tsx}', 'tests/**/*.{ts,tsx}'];
const toolFiles = ['tools/**/*.{ts,mts,mjs,cjs}', '*.config.{ts,mjs,cjs,js}'];

const projectPaths = [
    './tsconfig.tools.json',
    './packages/*/tsconfig.json',
    './docs/tsconfig.json',
];

const unusedImportsPlugin = unusedImportsPluginModule.default;
const vitestPlugin = vitestPluginModule.default;

const parserOptions = {
    sourceType: 'module',
    ecmaFeatures: {
        jsx: true,
    },
    project: projectPaths,
    noWarnOnMultipleProjects: true,
    ecmaVersion: 2021,
};

const importResolverSettings = {
    react: {
        version: 'detect',
    },
    'import-x/internal-regex': '^#(?:packages|test-vectors|tests|tools)(?:/|$)',
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
};

export default defineConfig(
    globalIgnores([
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
        'target',
        'target/**',
        'docs/.astro',
        'docs/.astro/**',
        'docs/dist',
        'docs/dist/**',
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
    ...typescriptEslintConfigs.stylisticTypeChecked,
    prettierPluginRecommended,
    {
        files: sourceFiles,
        languageOptions: {
            parser: typescriptParser,
            parserOptions,
            globals: {
                ...globals.browser,
                ...globals.node,
                ...globals.es2021,
                ...globals.commonjs,
            },
        },
        plugins: {
            'unused-imports': unusedImportsPlugin,
        },
        settings: importResolverSettings,
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
            '@typescript-eslint/no-unused-vars': OFF,
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
            'unused-imports/no-unused-imports': ERROR,
            'unused-imports/no-unused-vars': [
                ERROR,
                {
                    vars: 'all',
                    varsIgnorePattern: '^_',
                    args: 'after-used',
                    argsIgnorePattern: '^_',
                },
            ],
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
            'import-x/no-named-as-default': ERROR,
            'import-x/no-named-as-default-member': ERROR,
            'import-x/no-rename-default': ERROR,
            'import-x/no-duplicates': ERROR,
            'import-x/prefer-default-export': OFF,
            'import-x/extensions': [
                ERROR,
                'ignorePackages',
                {
                    js: 'never',
                    jsx: 'never',
                    cjs: 'never',
                    cts: 'never',
                    mjs: 'never',
                    mts: 'never',
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
    },
    {
        files: typeScriptFiles,
        rules: {
            '@typescript-eslint/no-unused-vars': OFF,
        },
    },
    {
        files: toolFiles,
        languageOptions: {
            parserOptions: {
                project: './tsconfig.tools.json',
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
        files: ['**/*.{cjs,cts,mts}'],
        languageOptions: {
            parser: typescriptParser,
            parserOptions,
            globals: {
                ...globals.node,
                ...globals.es2021,
                ...globals.commonjs,
            },
        },
    },
    {
        files: [...javaScriptFiles, '**/*.mts'],
        rules: {
            '@typescript-eslint/no-unsafe-assignment': OFF,
            '@typescript-eslint/no-unsafe-member-access': OFF,
            '@typescript-eslint/no-unsafe-call': OFF,
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
                ERROR,
                {
                    assertFunctionNames: ['expect', 'assert', 'expect*'],
                },
            ],
            'import-x/no-extraneous-dependencies': [
                ERROR,
                {
                    devDependencies: true,
                    // Vitest resolves this package name to the built public SDK entry point for public-package tests.
                    whitelist: ['sealed-lattice'],
                },
            ],
            'vitest/valid-expect': [ERROR, { minArgs: 1, maxArgs: 2 }],
            'vitest/no-focused-tests': ERROR,
            'vitest/no-disabled-tests': ERROR,
            'vitest/max-nested-describe': [ERROR, { max: 4 }],
        },
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
            '@typescript-eslint/explicit-function-return-type': OFF,
            '@typescript-eslint/explicit-module-boundary-types': OFF,
            '@typescript-eslint/no-require-imports': OFF,
            '@typescript-eslint/no-unsafe-assignment': OFF,
            '@typescript-eslint/no-unsafe-call': OFF,
            '@typescript-eslint/no-unsafe-member-access': OFF,
        },
    },
);
