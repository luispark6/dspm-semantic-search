# No shebang needed, this will be sourced
set -e

cat > "$PGDATA/pg_hba.conf" <<EOF
# Minimal pg_hba.conf
local   all        all                   scram-sha-256
host    ragdb      postgres   samenet    scram-sha-256
EOF
