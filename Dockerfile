# 1. Build the React site
FROM node:24-bookworm-slim AS client-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# 2. Compile the Express API
FROM node:24-bookworm-slim AS server-build
WORKDIR /build
COPY backend/package.json backend/package-lock.json ./
RUN npm ci
COPY backend/ ./
RUN npm run build

# 3. Runtime image: production dependencies only
FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=server-build /build/dist ./dist
COPY --from=client-build /build/dist ./client
ENV STATIC_DIR=/app/client
ENV STORAGE_DIR=/app/storage/encrypted
ENV PORT=8080
RUN mkdir -p /app/storage/encrypted
EXPOSE 8080
CMD ["sh", "-c", "node dist/db/migrate.js && node dist/db/seed.js && node dist/server.js"]
