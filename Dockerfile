FROM node:20-slim

# openssl برای ساخت CA/گواهی کاربران؛ openvpn فقط برای دستور genkey (تولید کلید tls-auth) استفاده می‌شود
RUN apt-get update && apt-get install -y openssl openvpn ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
