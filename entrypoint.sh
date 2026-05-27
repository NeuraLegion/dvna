#!/bin/bash
set -e

chmod +x /app/wait-for-it.sh

/bin/bash /app/wait-for-it.sh ${MYSQL_HOST:-mysql-db}:${MYSQL_PORT:-3306} -t 300 -- bash /app/startup.sh