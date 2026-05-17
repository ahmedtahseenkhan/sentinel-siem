#!/bin/bash
# Runs on primary first-start. Creates the replication user and physical slot.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER ${POSTGRES_REPLICATION_USER} WITH REPLICATION LOGIN PASSWORD '${POSTGRES_REPLICATION_PASSWORD}';
    SELECT pg_create_physical_replication_slot('replica_slot');
EOSQL
