import { fileURLToPath } from 'node:url';
export default {
  title: 'Grantline',
  description: 'Operate your identity security workspace.',
  base: '/docs/',
  srcDir: 'guide',
  outDir: '../web/dist/docs',
  vite: { resolve: { alias: { vue: fileURLToPath(new URL('../../web/node_modules/vue', import.meta.url)) } } },
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }]],
  themeConfig: {
    logo: '/brand/grantline-symbol.svg',
    nav: [{ text: 'Documentation', link: '/' }, { text: 'Install', link: '/install/docker' }],
    sidebar: [
      { text: 'Get started', items: [{ text: 'Introduction', link: '/' }, { text: 'Architecture', link: '/architecture' }, { text: 'Docker Compose', link: '/install/docker' }, { text: 'Kubernetes', link: '/install/kubernetes' }] },
      { text: 'Use Grantline', items: [{ text: 'Accounts & SSO', link: '/authentication/' }, { text: 'Integrations', link: '/integrations/' }, { text: 'Supported sources', link: '/integrations/supported-sources' }, { text: 'Permissions', link: '/integrations/permissions' }, { text: 'Investigations & policy', link: '/policies/' }, { text: 'OWASP mapping', link: '/policies/owasp-nhi-mapping' }] },
      { text: 'Operate', items: [{ text: 'Configuration', link: '/operations/configuration' }, { text: 'Metadata & credentials', link: '/operations/metadata-handling' }, { text: 'Backup & recovery', link: '/operations/backup' }, { text: 'Upgrade & troubleshooting', link: '/operations/upgrades' }, { text: 'API & CLI', link: '/reference/api' }, { text: 'Compatibility', link: '/reference/compatibility' }] }
    ],
    search: { provider: 'local' },
    footer: { message: 'Apache-2.0 · Self-hosted identity security', copyright: 'Grantline contributors' }
  }
};
