/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        h: {
          bg:     '#050a0e',
          panel:  '#0a1018',
          surface:'#0d1520',
          border: '#1a2744',
          bright: '#1e3a5f',
          green:  '#00ff41',
          gdim:   '#00cc33',
          red:    '#ff073a',
          rdim:   '#cc052e',
          cyan:   '#00d4ff',
          cdim:   '#00a8cc',
          yellow: '#ffb800',
          orange: '#ff6b35',
          purple: '#bf5af2',
          pdim:   '#9945c4',
          white:  '#e8edf4',
          text:   '#b8c5d6',
          muted:  '#5a6f8a',
          dark:   '#3a4f6a',
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
        display: ['"Orbitron"', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '1rem' }],
        '3xs': ['0.5rem',   { lineHeight: '0.75rem' }],
      },
      animation: {
        'blink':    'blink 1s step-end infinite',
        'glow':     'glow 2s ease-in-out infinite',
        'slideup':  'slideup 0.25s ease-out',
        'fadein':   'fadein 0.4s ease-out',
        'stream':   'stream 1.5s linear infinite',
        'scanline': 'scanline 6s linear infinite',
      },
      keyframes: {
        blink:    { '0%,100%': { opacity: '1' }, '50%': { opacity: '0' } },
        glow:     { '0%,100%': { opacity: '0.8' }, '50%': { opacity: '1' } },
        slideup:  { '0%': { transform: 'translateY(8px)', opacity: '0' }, '100%': { transform: 'translateY(0)', opacity: '1' } },
        fadein:   { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        stream:   { '0%': { backgroundPosition: '0 0' }, '100%': { backgroundPosition: '0 30px' } },
        scanline: { '0%': { top: '-10%' }, '100%': { top: '110%' } },
      },
    },
  },
  plugins: [],
}