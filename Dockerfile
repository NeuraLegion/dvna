# Damn Vulnerable NodeJS Application

FROM node:8-stretch
LABEL MAINTAINER="Subash SN"

WORKDIR /app

RUN printf 'deb http://archive.debian.org/debian stretch main\ndeb http://archive.debian.org/debian-security stretch/updates main\n' > /etc/apt/sources.list \
  && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive \
  && apt-get update -o Acquire::Check-Valid-Until=false \
  && apt-get install -y --no-install-recommends \
    python \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install

COPY . .
RUN chmod +x /app/entrypoint.sh /app/startup.sh /app/wait-for-it.sh

EXPOSE 9090

CMD ["/bin/sh", "-c", "if [ -n \"$MYSQL_HOST\" ] || [ -n \"$DATABASE_URL\" ]; then exec /app/entrypoint.sh; else echo 'Starting DVNA without MySQL; DB-backed features may be unavailable'; exec node server.js; fi"]