import mdx from '@astrojs/mdx';
import StarlightIntegration from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

const normalizeBase = (value: string | undefined): string => {
    const trimmed = (value ?? '/').trim();

    if (!trimmed || trimmed === '/') {
        return '/';
    }

    return `/${trimmed.replace(/^\/+|\/+$/g, '')}`;
};

// Serve docs from the repo subpath on GitHub Pages, but keep local runs at root.
const docsBase = normalizeBase(
    process.env.DOCS_BASE_PATH ??
        (process.env.GITHUB_ACTIONS === 'true' ? '/sealed-lattice' : '/'),
);

export default defineConfig({
    site: 'https://tenemo.github.io',
    base: docsBase,
    integrations: [
        StarlightIntegration({
            title: 'sealed-lattice',
            description:
                'Browser-native documentation for sealed-lattice, a post-quantum voting research package with a deliberately narrow public surface.',
            disable404Route: true,
            social: [
                {
                    icon: 'github',
                    label: 'GitHub',
                    href: 'https://github.com/Tenemo/sealed-lattice',
                },
            ],
            customCss: ['./src/styles/custom.css'],
            sidebar: [
                {
                    label: 'Guides',
                    items: [
                        'guides/getting-started',
                        'guides/runtime-and-compatibility',
                        'guides/browser-and-worker-usage',
                        'guides/security-and-non-goals',
                    ],
                },
                {
                    label: 'Protocol spec',
                    items: [
                        'spec',
                        'spec/library-invariants',
                        'spec/api-contract',
                    ],
                },
                {
                    label: 'API reference',
                    items: [
                        'api',
                        'api/root-package',
                        {
                            label: 'Generated reference',
                            collapsed: true,
                            autogenerate: {
                                directory: 'api/reference',
                            },
                        },
                    ],
                },
            ],
        }),
        mdx(),
    ],
});
