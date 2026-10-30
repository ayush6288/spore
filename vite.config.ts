import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

/**
 * SPORE ships as one file. There is no server, no asset host, no CDN and no
 * external stylesheet: the HTML document is the protocol.
 */
export default defineConfig({
  base: './',
  plugins: [
    viteSingleFile({
      removeViteModuleLoader: true,
      useRecommendedBuildConfig: true,
    }),
  ],
  build: {
    target: 'es2022',
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    emptyOutDir: true,
    reportCompressedSize: false,
    chunkSizeWarningLimit: 4096,
  },
});
