FROM node:lts-slim

USER node

WORKDIR /app

COPY package.json ./

RUN npm install

COPY . .

EXPOSE 3000

# Fixed: Added HEALTHCHECK instruction
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost:3000 || exit 1

CMD [ "npm", "start" ]

