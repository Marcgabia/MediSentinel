/** @type {import('tailwindcss').Config} */

// Every colour below is a CSS variable (see src/styles/input.css). Light values live in :root,
// dark values in html.dark, so every existing utility class (bg-white, text-slate-700,
// bg-red-50 …) follows the selected theme without per-page `dark:` variants.
const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
const themed = (name) => Object.fromEntries(SHADES.map((s) => [s, `rgb(var(--${name}-${s}) / <alpha-value>)`]));

export default {
  darkMode: 'class',
  content: ['./views/**/*.xian', './public/js/**/*.js', './utils/viewHelpers.js'],
  theme: {
    extend: {
      colors: {
        white: 'rgb(var(--surface) / <alpha-value>)',
        surface: 'rgb(var(--surface) / <alpha-value>)',
        canvas: 'rgb(var(--canvas) / <alpha-value>)',
        ink: 'rgb(var(--ink) / <alpha-value>)',
        onbrand: 'rgb(var(--onbrand) / <alpha-value>)',
        slate: themed('slate'),
        brand: themed('brand'),
        navy: themed('brand'),
        emerald: themed('emerald'),
        red: themed('red'),
        amber: themed('amber'),
        orange: themed('orange'),
        violet: themed('violet'),
        sky: themed('sky')
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'system-ui', '-apple-system', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Consolas', 'Liberation Mono', 'monospace']
      },
      boxShadow: {
        card: '0 1px 2px rgb(var(--shadow) / 0.06), 0 1px 3px rgb(var(--shadow) / 0.04)',
        pop: '0 12px 32px -8px rgb(var(--shadow) / 0.25), 0 4px 8px -4px rgb(var(--shadow) / 0.12)'
      }
    }
  },
  plugins: []
};
