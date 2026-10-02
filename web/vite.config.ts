import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 8080,
    strictPort: true,
    proxy: Object.fromEntries(
      ["/api", "/healthz", "/readyz", "/docs"].map((path) => [
        path,
        { target: "http://127.0.0.1:8082", changeOrigin: false },
      ]),
    ),
  },
  build: { sourcemap: false },
});
