# Dockerfile otimizado para Fly.io
FROM node:20-alpine AS builder

WORKDIR /app

# Instala dependências
COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# Copia código fonte
COPY . .

# Build TypeScript
RUN npm run build

# Imagem final
FROM node:20-alpine

WORKDIR /app

# Copia apenas o necessário
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

# Usuário não-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
USER nodejs

# Expõe porta
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start
CMD ["node", "dist/index.js"]
```

## 5. .dockerignore
```
node_modules
npm-debug.log
dist
.env
.env.*
.git
.gitignore
*.md
.vscode
.idea
coverage
.DS_Store
