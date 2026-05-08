import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Outfit", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      colors: {
        // Dark theme surfaces
        "dark-bg": "#0d1117",
        "dark-surface": "#161b22",
        "dark-hover": "#21262d",
        "dark-border": "#30363d",
        // Text
        "dark-text": "#e6edf3",
        "dark-muted": "#8b949e",
        // Accent
        "accent-blue": "#58a6ff",
        "accent-blue-dim": "#388bfd",
        "accent-gold": "#f6b73c",
        "accent-gold-dim": "#f08a24",
        // Status
        "status-green": "#3fb950",
        "status-red": "#f85149",
        "status-amber": "#d29922",
      },
      animation: {
        "gradient-shift": "gradientShift 8s ease infinite",
        "pulse-slow": "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "float": "float 6s ease-in-out infinite",
      },
      keyframes: {
        gradientShift: {
          "0%, 100%": { backgroundPosition: "0% 50%" },
          "50%": { backgroundPosition: "100% 50%" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-12px)" },
        },
      },
      backgroundSize: {
        "300%": "300%",
      },
    },
  },
  plugins: [],
};

export default config;
