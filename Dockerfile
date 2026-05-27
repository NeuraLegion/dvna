# Damn Vulnerable NodeJS Application

FROM node:20-bookworm-slim
LABEL MAINTAINER "Subash SN"

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    make \
    g++ \
    libxml2-dev \
    libxslt1-dev \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install

COPY . .
RUN chmod +x /app/entrypoint.sh

EXPOSE 9090

CMD ["bash", "/app/entrypoint.sh"]