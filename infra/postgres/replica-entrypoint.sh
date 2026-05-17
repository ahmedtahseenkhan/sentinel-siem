#!/bin/bash
# Replica entrypoint — runs pg_basebackup from primary then starts standby.
set -e

DATA_DIR=/var/lib/postgresql/data

if [ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
    echo "Replica data directory is empty — performing initial pg_basebackup from $PRIMARY_HOST"
    until pg_isready -h "$PRIMARY_HOST" -U "$POSTGRES_REPLICATION_USER"; do
        echo "Waiting for primary..."
        sleep 2
    done

    PGPASSWORD="$POSTGRES_REPLICATION_PASSWORD" pg_basebackup \
        -h "$PRIMARY_HOST" \
        -U "$POSTGRES_REPLICATION_USER" \
        -D "$DATA_DIR" \
        -X stream \
        -P \
        -R \
        -S replica_slot

    chmod 0700 "$DATA_DIR"
    chown -R postgres:postgres "$DATA_DIR"
    echo "Base backup complete — starting standby"
fi

# Hand off to the standard postgres entrypoint to start as standby
exec docker-entrypoint.sh postgres
