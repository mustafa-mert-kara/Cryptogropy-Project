FROM node:23-alpine

WORKDIR /usr/src/app

COPY . .

RUN npm install && npm install mongodb

EXPOSE 5000

CMD [ "npm","run", "dev" ] 