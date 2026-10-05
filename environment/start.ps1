# start.ps1
# PowerShell equivalent of start.sh for Windows with proper variable handling

# --- Setup ---
$ErrorActionPreference = "Stop"  # Stop on errors

Set-Location $PSScriptRoot

if (-not (Test-Path ".env")) {
    throw "Missing environment/.env. Copy .env.example to .env and replace every value."
}

Get-Content ".env" | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $name, $value = $line -split "=", 2
        if (-not $value) { throw "Invalid .env entry: $line" }
        [Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), "Process")
    }
}

$requiredVars = @(
    "JWT_SECRET", "MYSQL_ROOT_PASSWORD", "AUTH_DB_PASSWORD", "LOG_DB_PASSWORD",
    "CA_READER_PASSWORD", "REVOKER_PASSWORD", "LAB_ROOT_PASSWORD", "LAB_SSH_PASSWORD"
)
foreach ($name in $requiredVars) {
    $value = [Environment]::GetEnvironmentVariable($name, "Process")
    if ([string]::IsNullOrWhiteSpace($value) -or $value.StartsWith("replace-")) {
        throw "Set $name to a non-placeholder value in environment/.env."
    }
}
Write-Host ""
Write-Host "--- Building Docker containers ---"
Write-Host ""

docker build -t client -f Images/client/Dockerfile .
docker build --build-arg "LAB_ROOT_PASSWORD=$env:LAB_ROOT_PASSWORD" --build-arg "LAB_SSH_PASSWORD=$env:LAB_SSH_PASSWORD" -t fw1 -f Images/fw1/Dockerfile .
docker build --build-arg "LAB_ROOT_PASSWORD=$env:LAB_ROOT_PASSWORD" --build-arg "LAB_SSH_PASSWORD=$env:LAB_SSH_PASSWORD" -t fw2 -f Images/fw2/Dockerfile .
docker build --build-arg "LAB_ROOT_PASSWORD=$env:LAB_ROOT_PASSWORD" --build-arg "LAB_SSH_PASSWORD=$env:LAB_SSH_PASSWORD" -t caserver -f Images/caserver/Dockerfile .
docker build --build-arg "LAB_ROOT_PASSWORD=$env:LAB_ROOT_PASSWORD" --build-arg "LAB_SSH_PASSWORD=$env:LAB_SSH_PASSWORD" -t webserver -f Images/webserver/Dockerfile .
docker build --build-arg "LAB_ROOT_PASSWORD=$env:LAB_ROOT_PASSWORD" --build-arg "LAB_SSH_PASSWORD=$env:LAB_SSH_PASSWORD" --build-arg "MYSQL_ROOT_PASSWORD=$env:MYSQL_ROOT_PASSWORD" --build-arg "AUTH_DB_PASSWORD=$env:AUTH_DB_PASSWORD" --build-arg "JWT_SECRET=$env:JWT_SECRET" -t authserver -f Images/authserver/Dockerfile .

# Build logserver with build args
docker build `
  -f Images/logserver/Dockerfile `
  --build-arg "LAB_ROOT_PASSWORD=$env:LAB_ROOT_PASSWORD" `
  --build-arg "LAB_SSH_PASSWORD=$env:LAB_SSH_PASSWORD" `
  --build-arg "MYSQL_ROOT_PASSWORD=$env:MYSQL_ROOT_PASSWORD" `
  --build-arg DB_USER_LOGAPP=logapp `
  --build-arg "DB_PASS_LOGAPP=$env:LOG_DB_PASSWORD" `
  --build-arg DB_USER_READONLY=ca_reader `
  --build-arg "DB_PASS_READONLY=$env:CA_READER_PASSWORD" `
  --build-arg DB_USER_REVOKE=revoker `
  --build-arg "DB_PASS_REVOKE=$env:REVOKER_PASSWORD" `
  -t logserver .

# --- Start lab ---
kathara lrestart --noterminals --no-shared --no-hosthome
kathara lconfig -n client --add INTERNET

Write-Host ""
Write-Host "--- Running Startup Scripts ---"
Write-Host ""

$servers = "client","fw1","fw2","caserver","webserver","authserver","logserver"

foreach ($server in $servers) {
    try {
        kathara exec $server "/root/$server.startup"
    } catch {
        Write-Host "Warning: Startup script failed for $server, continuing..."
    }
}

# Copy CA certificate to client
$CASERVER = (docker ps --filter "name=caserver" --format "{{.Names}}").Trim()
$CLIENT = (docker ps --filter "name=client" --format "{{.Names}}").Trim()

docker cp "${CASERVER}:/etc/ssl/ca/certs/ca.cert.pem" "./ca.cert.pem"
docker cp "./ca.cert.pem" "${CLIENT}:/usr/local/share/ca-certificates/ca.crt"

kathara exec client "update-ca-certificates"

# Process CSRs for logserver, webserver, authserver
$targetServers = "logserver","webserver","authserver"

foreach ($server in $targetServers) {
    Write-Host ""
    Write-Host "--- Processing CSR for $server ---"

    $SERVER_CONTAINER = (docker ps --filter "name=$server" --format "{{.Names}}").Trim()
    Write-Host "$server container: $SERVER_CONTAINER"

    $CSR_PATH = "/etc/ssl/$server/$server.csr"
    $CERT_PATH = "/etc/ssl/$server/$server.crt"
    $CA_CERT_PATH = "/etc/ssl/$server/ca.cert.pem"

    # Move CSR and key from server to local
    Write-Host "Copying CSR and key from $server to CA server..."
    docker cp "${SERVER_CONTAINER}:${CSR_PATH}" "./${server}.csr"
    docker cp "${SERVER_CONTAINER}:/etc/ssl/${server}/${server}.key" "./${server}.key"
    docker cp "./${server}.csr" "${CASERVER}:/root/${server}.csr"

    if ($server -in @("webserver","authserver")) {
        $EXT_SECTION = "server_client_cert"
    } elseif ($server -eq "logserver") {
        $EXT_SECTION = "server_cert"
    }

    # Sign CSR on CA server
    Write-Host "Signing CSR for $server on CA server..."
    kathara exec caserver "openssl ca -batch -config /etc/ssl/ca/openssl.cnf -extensions $EXT_SECTION -in /root/${server}.csr -out /root/${server}.crt -notext -md sha256"

    # Copy signed certificate back
    Write-Host "Copying signed certificate back to $server..."
    docker cp "${CASERVER}:/root/${server}.crt" "./${server}.crt"
    docker cp "./${server}.crt" "${SERVER_CONTAINER}:${CERT_PATH}"

    # Copy CA cert as well
    docker cp "./ca.cert.pem" "${SERVER_CONTAINER}:${CA_CERT_PATH}"

    # Cleanup temporary files
    kathara exec caserver "rm /root/${server}.csr /root/${server}.crt"
    Remove-Item "./${server}.csr","./${server}.crt","./${server}.key" -ErrorAction SilentlyContinue

    # Run main server service
    Write-Host "Starting $server main service..."
    try {
        kathara exec $server "/root/${server}.startserver"
    } catch {
        Write-Host "Warning: Starting $server service failed, continuing..."
    }
}

# Start CA server main service
Write-Host "--- Starting CA server main service ---"
try {
    kathara exec caserver "/root/caserver.startserver"
} catch {
    Write-Host "Warning: CA server service failed to start."
}

# Issue admin certificate from authserver
kathara exec authserver "curl --max-time 5 --cacert /etc/ssl/authserver/ca.cert.pem --key /etc/ssl/authserver/authserver.key --cert /etc/ssl/authserver/authserver.crt -X POST -H 'Content-Type: application/json' -d '{\"cn\": \"ps\"}' -o admin_cert.zip https://caserver/issue"

$AUTHSERVER = (docker ps --filter "name=authserver" --format "{{.Names}}").Trim()
docker cp "${AUTHSERVER}:/var/www/authserver/admin_cert.zip" "./admin_cert.zip"
docker cp "./admin_cert.zip" "${CLIENT}:/admin_cert.zip"
Remove-Item "./admin_cert.zip" -ErrorAction SilentlyContinue
Remove-Item "./ca.cert.pem" -ErrorAction SilentlyContinue

# Delete schema file from logserver
Write-Host "--- Deleting schema file from logserver ---"
try { kathara exec logserver "rm -f /var/www/logserver/logserver_schema.sql" } catch {}

# Create super cleanup script
$cleanupScript = @"
#!/bin/bash
rm -rf /root/* 2>/dev/null || true
rm -rf /tmp/* 2>/dev/null || true
history -c 2>/dev/null || true
rm -f /root/.bash_history /home/*/.bash_history 2>/dev/null || true
"@

Set-Content -Path "/tmp/super_cleanup.sh" -Value $cleanupScript -Encoding UTF8

Write-Host ""
Write-Host "--- Waiting a bit to let services finish writing files ---"
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "--- Running SUPER CLEANUP in all containers ---"
foreach ($server in "client","fw1","fw2","caserver","webserver","authserver","logserver") {
    Write-Host "Cleaning $server ..."
    $SERVER_CONTAINER = (docker ps --filter "name=$server" --format "{{.Names}}").Trim()
    docker cp "/tmp/super_cleanup.sh" "${SERVER_CONTAINER}:/root/super_cleanup.sh"
    try { kathara exec $server "/root/super_cleanup.sh" } catch {}
    try { kathara exec $server "rm -f /root/super_cleanup.sh" } catch {}
}

# Remove local copy
Remove-Item "/tmp/super_cleanup.sh" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== System started and all traces in /root and /tmp removed ==="
