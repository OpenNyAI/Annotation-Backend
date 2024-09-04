#!/bin/bash

python3 -m venv .venv
source .venv/bin/activate
pip3 install alembic psycopg2-binary

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

alembic upgrade head