import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: {
    target: 'es2022',
  },
  test: {
    environment: 'node',
    globals: false,
    include: ['src/__tests__/**/*.test.ts'],
    typecheck: {
      enabled: false,
      tsconfig: './tsconfig.json',
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/index.ts',
        'src/errors/index.ts',
        'src/crypto/index.ts',
        'src/types/**',
        'src/__tests__/**',
        'src/**/*.d.ts',
      ],
      thresholds: {
        lines: 90,
        branches: 80,
        functions: 90,
      },
    },
  },
});
