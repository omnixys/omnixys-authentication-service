/** @type {import('typedoc').TypeDocOptions} */
module.exports = {
  // Output-Verzeichnis
  out: 'docs',

  // Haupt-Einstiegspunkt (expand = alle Module im Ordner src)
  entryPoints: ['src'],
  entryPointStrategy: 'expand',

  // Anzeigeoptionen
  name: 'Omnixys Authentication API Documentation',
  includeVersion: true,
  readme: './README.md',
  lang: 'en', // statt htmlLang

  // Theme-Konfiguration
  theme: 'default', // → Standard HTML Theme
  // plugin: ['typedoc-plugin-markdown'],
  // theme: 'markdown'  → falls du Markdown-Ausgabe willst (z. B. für mkdocs)

  // Sichtbarkeitsfilter
  excludePrivate: true,
  excludeProtected: false,
  excludeExternals: true,

  // Validierung
  validation: {
    invalidLink: true,
  },

  // Saubere URLs für GitHub Pages (optional)
  cleanOutputDir: true, // löscht alten Inhalt von /docs bei jedem Build

  // Branding über Custom CSS
  customCss: 'public/theme.css',
};
