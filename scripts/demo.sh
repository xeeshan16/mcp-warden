#!/usr/bin/env sh
# Start the Docker Compose stack and run the scripted demo agent against it.
# Writes a .env with fresh random secrets the first time.
set -eu

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    secret() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }
    umask 077
    {
        echo "POSTGRES_PASSWORD=$(secret)"
        echo "WARDEN_ADMIN_TOKEN=$(secret)"
        echo "WARDEN_AUDIT_HASH_KEY=$(secret)"
    } > .env
    echo "wrote .env with random secrets (keep it out of version control)"
fi

docker compose up --build --detach
docker compose --profile demo run --rm demo
