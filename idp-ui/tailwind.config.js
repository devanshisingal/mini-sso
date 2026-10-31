/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        hennge: {
          blue: "#0F52BA",
          dark: "#0B2545",
          accent: "#00A896"
        }
      }
    },
  },
  plugins: [],
}
