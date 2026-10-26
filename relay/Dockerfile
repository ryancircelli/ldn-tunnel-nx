# Self-hosted relay. Build from this directory: docker build -t ldn-tunnel-relay .
# Node 24 runs the TypeScript directly (transform-types: the codec uses enums), so there is no build step.
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8080 DB_PATH=/data/relay.sqlite
COPY --from=deps /app/node_modules node_modules
COPY package.json release.json ./
COPY assets assets
COPY src src
RUN mkdir /data && chown node /data
VOLUME /data
EXPOSE 8080
USER node
CMD ["node", "--experimental-transform-types", "--disable-warning=ExperimentalWarning", "src/node/server.ts"]
