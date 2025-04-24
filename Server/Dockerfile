FROM node:23-alpine



WORKDIR /usr/src/app

COPY . .

RUN apt update \
    && apt -y install software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt update \
    && apt -y install python3.12.2 \
    && npm install && npm install mongodb && python3 -m pip install RC6Encryption


EXPOSE 5000

CMD [ "npm","run", "dev" ] 