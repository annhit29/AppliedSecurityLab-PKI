#!/usr/bin/env bash

# --- Setup ---
set -euo pipefail   # safer scripting

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
  echo "Missing environment/.env. Copy .env.example to .env and replace every value." >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source .env
set +a

required_vars=(
  JWT_SECRET MYSQL_ROOT_PASSWORD AUTH_DB_PASSWORD LOG_DB_PASSWORD
  CA_READER_PASSWORD REVOKER_PASSWORD LAB_ROOT_PASSWORD LAB_SSH_PASSWORD
)
for var_name in "${required_vars[@]}"; do
  value=${!var_name:-}
  if [[ -z "$value" || "$value" == replace-* ]]; then
    echo "Set $var_name to a non-placeholder value in environment/.env." >&2
    exit 1
  fi
done

common_build_args=(
  --build-arg "LAB_ROOT_PASSWORD=$LAB_ROOT_PASSWORD"
  --build-arg "LAB_SSH_PASSWORD=$LAB_SSH_PASSWORD"
)

echo ""
echo "--- Building Docker containers ---"
echo ""

docker build -t client -f Images/client/Dockerfile .
docker build "${common_build_args[@]}" -t fw1 -f Images/fw1/Dockerfile .
docker build "${common_build_args[@]}" -t fw2 -f Images/fw2/Dockerfile .
docker build "${common_build_args[@]}" -t caserver -f Images/caserver/Dockerfile .
docker build "${common_build_args[@]}" -t webserver -f Images/webserver/Dockerfile .
docker build "${common_build_args[@]}" \
  --build-arg "MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD" \
  --build-arg "AUTH_DB_PASSWORD=$AUTH_DB_PASSWORD" \
  --build-arg "JWT_SECRET=$JWT_SECRET" \
  -t authserver -f Images/authserver/Dockerfile .

# build logserver with build args for DB credentials
docker build \
  "${common_build_args[@]}" \
  -f Images/logserver/Dockerfile \
  --build-arg DB_USER_LOGAPP=logapp \
  --build-arg "DB_PASS_LOGAPP=$LOG_DB_PASSWORD" \
  --build-arg DB_USER_READONLY=ca_reader \
  --build-arg "DB_PASS_READONLY=$CA_READER_PASSWORD" \
  --build-arg DB_USER_REVOKE=revoker \
  --build-arg "DB_PASS_REVOKE=$REVOKER_PASSWORD" \
  --build-arg "MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD" \
  -t logserver .


# Use lines below for running from images

#echo ""
#echo "--- Loading pre-built Docker Images ---"
#echo ""

#docker load -i Prebuilt-Images/client.tar
#docker load -i Prebuilt-Images/fw1.tar
#docker load -i Prebuilt-Images/fw2.tar
#docker load -i Prebuilt-Images/caserver.tar
#docker load -i Prebuilt-Images/webserver.tar
#docker load -i Prebuilt-Images/authserver.tar
#docker load -i Prebuilt-Images/logserver.tar


# Start lab
kathara lrestart --noterminals --no-shared --no-hosthome

kathara lconfig -n client --add INTERNET

echo ""
echo "--- Running Startup Scripts ---"
echo ""

kathara exec client /root/client.startup || true
kathara exec fw1 /root/fw1.startup || true
kathara exec fw2 /root/fw2.startup || true
kathara exec caserver /root/caserver.startup || true
kathara exec webserver /root/webserver.startup || true
kathara exec authserver /root/authserver.startup || true
kathara exec logserver /root/logserver.startup || true

CASERVER=$(docker ps --filter "name=caserver" --format "{{.Names}}")
CLIENT=$(docker ps --filter "name=client" --format "{{.Names}}")
docker cp "$CASERVER":"/etc/ssl/ca/certs/ca.cert.pem" .
docker cp "./ca.cert.pem" "$CLIENT":"/usr/local/share/ca-certificates/ca.crt"

#docker cp "$CASERVER":"/etc/ssl/client/client.p12" .
#docker cp "./client.p12" "$CLIENT":"/admin_cert.p12"

#rm -f ./client.p12

kathara exec client update-ca-certificates

for SERVER in "logserver" "webserver" "authserver"; do
  echo ""
  echo "--- Processing CSR for $SERVER ---"

  SERVER_CONTAINER=$(docker ps --filter "name=${SERVER}" --format "{{.Names}}")
  echo "$SERVER container: $SERVER_CONTAINER"

  CSR_PATH="/etc/ssl/${SERVER}/${SERVER}.csr"
  CERT_PATH="/etc/ssl/${SERVER}/${SERVER}.crt"
  CA_CERT_PATH="/etc/ssl/${SERVER}/ca.cert.pem"

  # --- Move CSR from server to CA server ---
  echo "Copying CSR from $SERVER to CA server..."
  docker cp "$SERVER_CONTAINER":"$CSR_PATH" .
  docker cp "$SERVER_CONTAINER":"/etc/ssl/${SERVER}/${SERVER}.key" .
  docker cp "./${SERVER}.csr" "$CASERVER":"/root/${SERVER}.csr"

  case "$SERVER" in
    webserver|authserver)
      EXT_SECTION="server_client_cert"
      ;;
    logserver)
      EXT_SECTION="server_cert"
      ;;
  esac

  # --- Sign CSR on CA server ---
  echo "Signing CSR for $SERVER on CA server..."
  kathara exec caserver "openssl ca -batch -config /etc/ssl/ca/openssl.cnf \
    -extensions $EXT_SECTION \
    -in /root/${SERVER}.csr \
    -out /root/${SERVER}.crt \
    -notext -md sha256"

  # --- Move signed certificate back ---
  echo "Copying signed certificate back to $SERVER..."
  docker cp "$CASERVER":"/root/${SERVER}.crt" .
  docker cp "./${SERVER}.crt" "$SERVER_CONTAINER":"$CERT_PATH"

  # --- Copy CA cert as well ---
  docker cp "./ca.cert.pem" "$SERVER_CONTAINER":"$CA_CERT_PATH"

  # --- Cleanup temporary files ---
  kathara exec caserver "rm /root/${SERVER}.csr /root/${SERVER}.crt"
  rm "./${SERVER}.csr" "./${SERVER}.crt" "./${SERVER}.key"

  # --- Run remaining server instances ---
  echo "Starting $SERVER main service..."
  kathara exec "$SERVER" -- /root/${SERVER}.startserver || true
done

echo "--- Starting CA server main service ---"
kathara exec caserver /root/caserver.startserver || true

kathara exec authserver "curl --max-time 5 --cacert /etc/ssl/authserver/ca.cert.pem \
  --key  /etc/ssl/authserver/authserver.key --cert /etc/ssl/authserver/authserver.crt \
  -X POST -H 'Content-Type: application/json' -d '{\"cn\": \"ps\"}' -o admin_cert.zip https://caserver/issue"

AUTHSERVER=$(docker ps --filter "name=authserver" --format "{{.Names}}")
docker cp "$AUTHSERVER":"/var/www/authserver/admin_cert.zip" .
docker cp "./admin_cert.zip" "$CLIENT":"/admin_cert.zip"

rm -r ./admin_cert.zip

rm -f "./ca.cert.pem"

echo "--- Deleting schema file from logserver ---"
kathara exec logserver -- rm -f /var/www/logserver/logserver_schema.sql || true

cat << 'EOF' > /tmp/super_cleanup.sh
#!/bin/bash
# cleanup: remove all traces under /root and /tmp, and clear history

# Remove everything in /root (files & dirs)
rm -rf /root/* 2>/dev/null || true

# Remove everything in /tmp
rm -rf /tmp/* 2>/dev/null || true

# Clear bash history (in-memory and on disk)
history -c 2>/dev/null || true
rm -f /root/.bash_history /home/*/.bash_history 2>/dev/null || true
EOF

chmod +x /tmp/super_cleanup.sh


echo ""
echo "--- Waiting a bit to let services finish writing files ---"
sleep 5

echo ""
echo "--- Running SUPER CLEANUP in all containers ---"

for SERVER in client fw1 fw2 caserver webserver authserver logserver; do
    echo "Cleaning $SERVER ..."
    SERVER_CONTAINER=$(docker ps --filter "name=${SERVER}" --format "{{.Names}}")

    # Copy cleanup script into the container
    docker cp /tmp/super_cleanup.sh "${SERVER_CONTAINER}:/root/super_cleanup.sh"

    # Run it via kathara (no -c flags involved)
    kathara exec "$SERVER" -- /root/super_cleanup.sh || true

    # Delete the script itself from the container
    kathara exec "$SERVER" -- rm -f /root/super_cleanup.sh || true
done

# Remove local copy
rm -f /tmp/super_cleanup.sh

echo ""
echo "=== System started and all traces in /root and /tmp removed ==="
