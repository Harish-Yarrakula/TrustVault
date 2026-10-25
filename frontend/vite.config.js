import react from '@vitejs/plugin-react'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { cwd } from 'node:process'
import { defineConfig, loadEnv } from 'vite'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({ command, mode }) => {
  const isDevServer = command === 'serve'
  const env = loadEnv(mode, '.', 'VITE_')
  const configuredApiUrl = isDevServer
    ? env.VITE_API_URL?.trim() || 'http://localhost:8000'
    : '/'
  const sameOriginApi = configuredApiUrl === '/'
  const apiOrigin = sameOriginApi ? '' : new URL(configuredApiUrl).origin
  let s3UploadOrigin = ''
  if (env.VITE_S3_UPLOAD_ORIGIN) {
    let configuredS3Url
    try {
      configuredS3Url = new URL(env.VITE_S3_UPLOAD_ORIGIN)
    } catch {
      throw new Error('VITE_S3_UPLOAD_ORIGIN must be a valid HTTPS origin.')
    }
    if (
      configuredS3Url.protocol !== 'https:' ||
      configuredS3Url.origin !== env.VITE_S3_UPLOAD_ORIGIN.replace(/\/$/, '')
    ) {
      throw new Error('VITE_S3_UPLOAD_ORIGIN must be a valid HTTPS origin without a path.')
    }
    s3UploadOrigin = configuredS3Url.origin
  }
  const devConnectSources = isDevServer
    ? ' http://localhost:8000 ws://localhost:* ws://127.0.0.1:*'
    : ''
  const uploadConnectSource = s3UploadOrigin ? ` ${s3UploadOrigin}` : ''
  const scriptPolicy = isDevServer
    ? "script-src 'self' 'unsafe-inline'"
    : "script-src 'self'"
  const contentSecurityPolicy = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "form-action 'self'",
    scriptPolicy,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https://images.unsplash.com",
    `connect-src 'self'${apiOrigin ? ` ${apiOrigin}` : ''}${uploadConnectSource}${devConnectSources}`,
    "font-src 'self' data:",
  ].join('; ')
  const contentSecurityPolicyHeader = `${contentSecurityPolicy}; frame-ancestors 'none'`

  return {
    server: {
      headers: { 'Content-Security-Policy': contentSecurityPolicyHeader },
    },
    preview: {
      headers: { 'Content-Security-Policy': contentSecurityPolicyHeader },
    },
    plugins: [
      tailwindcss(),
      react(),
      {
        name: 'trustvault-content-security-policy',
        transformIndexHtml() {
          return [{
            tag: 'meta',
            attrs: {
              'http-equiv': 'Content-Security-Policy',
              content: contentSecurityPolicy,
            },
            injectTo: 'head',
          }]
        },
      },
      {
        name: 'trustvault-publish-documentation',
        apply: 'build',
        generateBundle() {
          const docsDirectory = resolve(cwd(), 'docs')
          for (const fileName of readdirSync(docsDirectory).filter((name) => name.endsWith('.html'))) {
            this.emitFile({
              type: 'asset',
              fileName: `docs/${fileName}`,
              source: readFileSync(resolve(docsDirectory, fileName)),
            })
          }
        },
      },
    ],
  }
})
