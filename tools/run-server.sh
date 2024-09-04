#!/bin/bash

if grep -qi microsoft /proc/version && grep -q WSL2 /proc/version; then
    HOST=$(hostname -I | awk '{print $1}')
    export LOCAL_POSTGRES_DATABASE_HOST=${HOST}
    echo "Setting Postgres host by WSL2 IP: ${HOST}"
else
    export LOCAL_POSTGRES_DATABASE_HOST=localhost
    echo "Setting Postgres host by docker-compose service name: postgres"
fi

set -a
source .env
set +a

uvicorn --port 8080 --host 0.0.0.0  --workers 4 app.server:app --reload
