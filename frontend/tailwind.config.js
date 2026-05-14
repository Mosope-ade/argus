/** @type {import('tailwindcss').Config} */
export default {
    content: [
      "./index.html",
      "./src/**/*.{js,ts,jsx,tsx}",
    ],
  
    theme: {
      extend: {
        colors: {
          background: "#080c12",
          surface: "#0d1117",
          border: "#1a2535",
  
          cyan: "#00d4ff",
          green: "#00ff9d",
          amber: "#ffc800",
          red: "#ff3c5a",
  
          textPrimary: "#e2e8f0",
          textMuted: "#4a6080",
        },
  
        fontFamily: {
          mono: ["JetBrains Mono", "monospace"],
          display: ["Syne", "sans-serif"],
        },
      },
    },
  
    plugins: [],
  };