/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Terminal color scheme
        terminal: {
          bg: '#0d1117',
          surface: '#161b22',
          border: '#30363d',
          green: '#39d353',
          red: '#f85149',
          yellow: '#d29922',
          cyan: '#58a6ff',
          orange: '#fb8500',
          purple: '#bc8cff',
          text: '#c9d1d9',
          muted: '#8b949e'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace']
      },
      animation: {
        'blink': 'blink 1s step-end infinite',
        'scan': 'scan 2s linear infinite',
        'pulse-green': 'pulse-green 2s ease-in-out infinite'
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0 }
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' }
        },
        'pulse-green': {
          '0%, 100%': { boxShadow: '0 0 5px #39d353' },
          '50%': { boxShadow: '0 0 20px #39d353, 0 0 40px #39d353' }
        }
      }
    },
  },
  plugins: [],
}
