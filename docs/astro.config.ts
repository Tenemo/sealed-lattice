import mdx from '@astrojs/mdx';
import StarlightIntegration from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

const docsBase =
    process.env.GITHUB_ACTIONS === 'true' ? '/sealed-lattice' : '/';

export default defineConfig({
    site: 'https://tenemo.github.io',
    base: docsBase,
    integrations: [
        StarlightIntegration({
            title: 'sealed-lattice',
            description:
                'Documentation for sealed-lattice transcript-core verification, safe election foundations, and ballot privacy proof-record boundaries.',
            disable404Route: true,
            components: {
                ThemeSelect: './src/components/ThemeToggle.astro',
            },
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
                        'guides/workspace-layout',
                        'guides/development-workflow',
                        'guides/security-and-non-goals',
                    ],
                },
                {
                    label: 'Protocol spec',
                    items: ['spec'],
                },
                {
                    label: 'API reference',
                    items: [
                        'api',
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
