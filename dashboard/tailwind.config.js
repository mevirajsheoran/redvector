/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        hbg:     '#050a0e',
        hpanel:  '#0a1018',
        hsurf:   '#0d1520',
        hborder: '#1a2744',
        hgreen:  '#00ff41',
        hred:    '#ff073a',
        hcyan:   '#00d4ff',
        hyellow: '#ffb800',
        horange: '#ff6b35',
        hpurple: '#bf5af2',
        hwhite:  '#e8edf4',
        htext:   '#b8c5d6',
        hmuted:  '#5a6f8a',
        hdark:   '#3a4f6a',
        hgdim:   '#00cc33',
      },
      fontFamily: {
        mono:    ['"JetBrains Mono"', 'Consolas', 'monospace'],
        display: ['"Orbitron"', 'monospace'],
      },
      animation: {
        'blink':   'blink 1s step-end infinite',
        'slideup': 'slideup 0.25s ease-out',
        'fadein':  'fadein 0.5s ease-out',
        'pulse2':  'pulse 2s ease-in-out infinite',
      },
      keyframes: {
        blink:   { '0%,100%': { opacity: 1 }, '50%': { opacity: 0 } },
        slideup: { '0%': { transform: 'translateY(8px)', opacity: 0 }, '100%': { transform: 'translateY(0)', opacity: 1 } },
        fadein:  { '0%': { opacity: 0 }, '100%': { opacity: 1 } },
      },
    },
  },
  plugins: [],
}
