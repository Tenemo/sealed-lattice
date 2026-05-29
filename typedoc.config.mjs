import { readFileSync } from 'node:fs';

import { typeDocEntryPoints } from './docs/typedoc/public-api-reference';

const generatedReferenceIntroPath = 'docs/typedoc/generated-reference-intro.md';
const generatedReferenceIntro = readFileSync(
    generatedReferenceIntroPath,
    'utf8',
);
const nonExternalMarkdownLinkPattern =
    /!?\[[^\]]*]\((?!https?:|mailto:|#|\/\/)([^)]+)\)/g;

if (nonExternalMarkdownLinkPattern.test(generatedReferenceIntro)) {
    throw new Error(
        `${generatedReferenceIntroPath} must not contain non-external markdown links. typedoc-plugin-markdown copies them as media and can recurse into generated output.`,
    );
}

/** @type {import('typedoc').TypeDocOptions} */
const config = {
    entryPoints: typeDocEntryPoints,
    entryPointStrategy: 'resolve',
    alwaysCreateEntryPointModule: true,
    tsconfig: 'docs/typedoc/tsconfig.json',
    plugin: ['typedoc-plugin-markdown', 'typedoc-plugin-frontmatter'],
    out: 'docs/src/content/docs/api/reference',
    router: 'module',
    readme: 'docs/typedoc/generated-reference-intro.md',
    entryFileName: 'index.md',
    navigationJson: 'docs/src/content/docs/api/reference/navigation.json',
    cleanOutputDir: true,
    githubPages: false,
    hideGenerator: true,
    disableSources: true,
    excludeExternals: true,
    excludePrivate: true,
    excludeProtected: true,
    excludeInternal: true,
    validation: {
        invalidLink: true,
        invalidPath: true,
        notDocumented: true,
        notExported: false,
        rewrittenLink: true,
    },
    treatValidationWarningsAsErrors: true,
    classPropertiesFormat: 'table',
    interfacePropertiesFormat: 'table',
    indexFormat: 'table',
    frontmatterGlobals: {
        editUrl: false,
    },
    readmeFrontmatter: {
        description: 'Export-driven symbol reference for the public API.',
        sidebar: {
            hidden: true,
        },
    },
};

export default config;
