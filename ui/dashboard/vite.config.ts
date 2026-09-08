import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

const backend = new URL(
  process.env.FERRUM2_DASHBOARD_BACKEND ?? "http://127.0.0.1:9090",
);
if (
  backend.protocol !== "http:" ||
  !["127.0.0.1", "[::1]"].includes(backend.hostname) ||
  backend.username ||
  backend.password ||
  backend.pathname !== "/"
) {
  throw new Error("Development backend must be a plain loopback HTTP origin");
}

export default defineConfig({
  plugins: [react(), viteSingleFile()],
  base: "./",
  publicDir: false,
  build: {
    sourcemap: false,
    target: "es2022",
    cssCodeSplit: false,
    reportCompressedSize: false,
  },
  server: {
    host: "127.0.0.1",
    strictPort: true,
    proxy: {
      "/api": {
        target: backend.origin,
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", (request) => {
            // Development is same-origin to the browser; the client still requires its token.
            request.setHeader("origin", backend.origin);
          });
        },
      },
    },
  },
});
