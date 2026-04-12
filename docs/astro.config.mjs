import mdx from '@astrojs/mdx';
import StarlightIntegration from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

export default defineConfig({
    site: 'https://tenemo.github.io',
    base: '/sealed-lattice',
    integrations: [
        StarlightIntegration({
            title: 'sealed-lattice',
            description:
                'Browser-native sealed-lattice documentation for the current public package surface and future post-quantum voting research.',
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
