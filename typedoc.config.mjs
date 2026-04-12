import { readFileSync } from 'node:fs';

import { typedocEntryPoints } from './typedoc/public-api-docs';

const generatedReferenceIntroPath = 'typedoc/generated-reference-intro.md';
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
    entryPoints: typedocEntryPoints,
    entryPointStrategy: 'resolve',
    alwaysCreateEntryPointModule: true,
    plugin: ['typedoc-plugin-markdown'],
    out: 'docs/src/content/docs/api/reference',
    router: 'member',
    readme: 'typedoc/generated-reference-intro.md',
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
        notExported: false,
    },
    classPropertiesFormat: 'table',
    interfacePropertiesFormat: 'table',
    indexFormat: 'table',
};

export default config;
