FROM node:14-slim

USER root

WORKDIR /app

COPY package*.json ./

COPY . .

RUN npm install

EXPOSE 22
EXPOSE 3000

CMD [ "npm", "start" ]

# Insecure practice: Running as root
