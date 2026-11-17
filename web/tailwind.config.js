/** @type {import('tailwindcss').Config} */
// Every colour resolves to a CSS variable holding an "r g b" triplet so that
// opacity modifiers (bg-surface/60) keep working and the light theme is one class swap.
const rgb = (name) => `rgb(var(--tg-${name}) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: rgb('bg'),
        surface: rgb('surface'),
        'surface-2': rgb('surface-2'),
        'surface-3': rgb('surface-3'),
        border: rgb('border'),
        'border-strong': rgb('border-strong'),
        text: rgb('text'),
        muted: rgb('muted'),
        faint: rgb('faint'),
        accent: rgb('accent'),
        'accent-soft': rgb('accent-soft'),
        success: rgb('success'),
        warning: rgb('warning'),
        danger: rgb('danger'),
      },
      borderRadius: {
        sm: '6px',
        DEFAULT: '10px',
        md: '10px',
        lg: '14px',
        xl: '18px',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'JetBrains Mono', 'Menlo', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
        '3xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      boxShadow: {
        card: '0 1px 2px 0 rgb(0 0 0 / 0.35), 0 1px 3px 0 rgb(0 0 0 / 0.2)',
        pop: '0 10px 30px -10px rgb(0 0 0 / 0.7)',
      },
      backgroundImage: {
        accent: 'linear-gradient(135deg, rgb(var(--tg-accent)) 0%, rgb(var(--tg-accent-2)) 100%)',
        'rail-active': 'linear-gradient(180deg, rgb(var(--tg-accent) / 0.25), rgb(var(--tg-accent) / 0.02))',
      },
      transitionDuration: {
        DEFAULT: '140ms',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-400px 0' },
          '100%': { backgroundPosition: '400px 0' },
        },
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'pop-in': {
          from: { opacity: '0', transform: 'translateY(-4px) scale(0.99)' },
          to: { opacity: '1', transform: 'translateY(0) scale(1)' },
        },
      },
      animation: {
        shimmer: 'shimmer 1.6s linear infinite',
        'fade-in': 'fade-in 140ms ease-out',
        'pop-in': 'pop-in 120ms ease-out',
      },
    },
  },
  plugins: [],
}
