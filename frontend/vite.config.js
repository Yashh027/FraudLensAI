import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const backendUrl = env.VITE_API_BASE_URL || "";

  return {
    plugins: [react()],

    // Base path for GitHub Pages. Use "/" for user sites (username.github.io)
    // or "/REPO_NAME/" for project sites (username.github.io/REPO_NAME).
    base: env.VITE_BASE_PATH || "/",

    server: {
      proxy: backendUrl
        ? undefined
        : {
            "/api": {
              target: "http://127.0.0.1:8000",
              changeOrigin: true,
            },
            "/health": {
              target: "http://127.0.0.1:8000",
              changeOrigin: true,
            },
          },
    },
  };
});