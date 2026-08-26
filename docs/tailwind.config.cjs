/**
 * Build the static Pages stylesheet without loading runtime code from a CDN:
 * npx --yes tailwindcss@3.4.17 -c docs/tailwind.config.cjs \
 *   -i docs/assets/css/tailwind.input.css -o docs/assets/css/tailwind.css --minify
 */
module.exports = {
  content: [
    "./docs/*.md",
    "./docs/_layouts/*.html",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["system-ui", "sans-serif"],
        mono: ["ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
