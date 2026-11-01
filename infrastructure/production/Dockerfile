FROM node:24-bookworm-slim
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates openssl && apt-get clean
RUN npm install --global pnpm@11.25.0
COPY . .
RUN pnpm install --frozen-lockfile
RUN NODE_OPTIONS=--max-old-space-size=1024 node scripts/run.mjs build
RUN mkdir -p apps/dashboard/.next/cache && chown -R node:node apps/dashboard/.next/cache
USER node
ENV NODE_ENV=production
CMD ["node","scripts/run.mjs","start"]
