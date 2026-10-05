#!/usr/bin/env python3
import base64
from datetime import datetime
from flask import Flask, abort, request, jsonify
import os
import socket
import mysql.connector #type: ignore

DB_USER_LOGAPP = os.getenv("DB_USER_LOGAPP")
DB_PASS_LOGAPP = os.getenv("DB_PASS_LOGAPP")
DB_USER_READONLY = os.getenv("DB_USER_READONLY")
DB_PASS_READONLY = os.getenv("DB_PASS_READONLY")
DB_USER_REVOKE = os.getenv("DB_USER_REVOKE")
DB_PASS_REVOKE = os.getenv("DB_PASS_REVOKE")

app = Flask(__name__)

def get_db_connection(db_name):
    return mysql.connector.connect(
        host="localhost",
        user=DB_USER_LOGAPP,
        password=DB_PASS_LOGAPP,
        database=db_name,
    )

def get_db_connection_readonly():
    return mysql.connector.connect(
        host="localhost", # localhost because logserver and db are in the same docker container
        user=DB_USER_READONLY,
        password=DB_PASS_READONLY,
        database="cert_archive_db",
    )

def get_db_connection_update():
    return mysql.connector.connect(
        host="localhost",
        user=DB_USER_REVOKE,
        password=DB_PASS_REVOKE,
        database="cert_archive_db"
    )

def _require_authserver():
    client_dn = request.headers.get("X-Client-Cert", "")
    if client_dn != "CN=authserver":
        abort(403, f"Unauthorized client: {client_dn}")
    
    client_ip = request.headers.get("X-Real-IP", request.remote_addr)
    if client_ip != "10.101.0.1":
        abort(403, f"Unauthorized IP: {client_ip}")

def _require_caserver():
    client_dn = request.headers.get("X-Client-Cert", "")
    if client_dn != "CN=caserver":
        abort(403, f"Unauthorized client: {client_dn}")
    client_ip = request.headers.get("X-Real-IP", request.remote_addr)
    if client_ip != "10.101.0.2":
        abort(403, f"Unauthorized IP {client_ip}, expected 10.101.0.2")


# Define allowed client DNs and their corresponding IPs
ALLOWED = {
    "CN=authserver": "10.101.0.1",
    "CN=caserver":   "10.101.0.2",
    "CN=webserver":  "10.100.0.1",
}

def _require_server():
    """
    check before saving logs if it's one of the 3 servers (ca, auth, web) <- as clients
    i.e. same idea as in ca_api.py L12-19
    """
    client_dn = request.headers.get("X-Client-Cert", "")
    if client_dn not in ALLOWED:
        abort(403, f"Unauthorized client: {client_dn}")

    expected_ip = ALLOWED[client_dn]
    client_ip = request.headers.get("X-Real-IP", request.remote_addr)
    if client_ip != expected_ip:
        abort(403, f"Unauthorized IP {client_ip}, expected {expected_ip}")

LOG_DIR = "/var/log/logserver"
os.makedirs(LOG_DIR, exist_ok=True)

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except socket.herror:
        hostname = ip
    return hostname

# table1
@app.route("/archive/cert", methods=["POST"])
def archive_cert():
    """Certificate archive endpoint to store issued certificates in the database"""
    _require_caserver() # only caserver can send issued certificates to logserver

    payload = request.get_json(force=True)
    required = [
        "serial_number", "uid", "issue_time",
        "certificate_pem", "public_key_pem",
        "private_key_cipher", "enc_algo",
        "enc_nonce", "enc_tag", "status",
    ]
    for k in required:
        if k not in payload:
            abort(400, f"Missing field {k}")

    conn = get_db_connection("cert_archive_db") #AND we establish a append-only (INSERT) connection for archiving certificates
    cur = conn.cursor()

    # Convert base64 -> bytes (i.e. the binary data) for VARBINARY columns
    pk_cipher = base64.b64decode(payload["private_key_cipher"])
    enc_nonce = base64.b64decode(payload["enc_nonce"])
    enc_tag   = base64.b64decode(payload["enc_tag"])

    cur.execute(
        """
        INSERT INTO archived_certificates
        (serial_number, uid, issue_time,
         certificate_pem, public_key_pem,
         private_key_cipher, enc_algo, enc_nonce, enc_tag,
         status, revoked_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL)
        """,
        (
            int(payload["serial_number"]),
            payload["uid"],
            payload["issue_time"].replace("T", " ").replace("Z", ""),
            payload["certificate_pem"],
            payload["public_key_pem"],
            pk_cipher,
            payload["enc_algo"],
            enc_nonce,
            enc_tag,
            payload["status"],
        ),
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/archive/cert/<int:serial>", methods=["GET"])
def get_archived_cert(serial):
    """
    In case of recovery operations (<- this logic belongs only inside the CA, not inside the logserver), only the CA Server can retrieve previously issued certificates from the logserver database.
    This endpoint allows the CA Server to fetch archived certificates from the logserver database.
    """
    _require_caserver() # only caserver can retrieve archived certificates
    conn = get_db_connection_readonly() # AND we establish a read-only (SELECT) connection for retrieval of certificates

    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT *
        FROM archived_certificates
        WHERE serial_number = %s
        """,
        (serial,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        abort(404, "Not found")

    # Convert Binary fields -> base64 for JSON response
    row["private_key_cipher"] = base64.b64encode(row["private_key_cipher"]).decode()
    row["enc_nonce"] = base64.b64encode(row["enc_nonce"]).decode()
    row["enc_tag"] = base64.b64encode(row["enc_tag"]).decode()
    return jsonify(row)

# Note: this function is the only one that modifies existing entries.
# Other functions only insert new entries i.e. append-only.
@app.route("/archive/cert/revoke", methods=["POST"])
def archive_revoke():
    """Certificate revocation endpoint to mark a certificate as revoked in the database"""
    _require_caserver() # only caserver can revoke certificates in logserver
    
    if not request.json:
        abort(400, "Missing JSON content with serial_number")
    serial = request.json.get("serial_number")

    conn = get_db_connection_update() # AND we establish a UPDATE-only connection for modifying status and revoked_at fields of archived certificates
    cur = conn.cursor()
    cur.execute(
        "UPDATE archived_certificates SET status='revoked', revoked_at=NOW() WHERE serial_number=%s",
        (serial,)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "ok"})

# table2
@app.route("/archive/userdb", methods=["POST"])
def archive_userdb():
    _require_authserver() # only authserver can send userdb backups to logserver
    payload = request.get_json(force=True)

    conn = get_db_connection("userdb_backup_db")
    cur = conn.cursor()
    
    snapshot_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # logserver generates the snapshot timestamp itself

    cur.execute(
        """
        INSERT INTO user_snapshots (snapshot_ts, uid, lastname, firstname, email, pwd_hash)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            snapshot_ts,
            payload["uid"],
            payload["lastname"],
            payload["firstname"],
            payload["email"],
            payload["pwd_hash"], # is already a hashed password created by the authserver’s password hashing module
        )
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status":"ok"})

# table3.1
@app.route("/archive/log", methods=["POST"])
def archive_log():
    """Log endpoint to store logs in the database"""
    _require_server()
    payload = request.get_json(force=True)
    if "message" not in payload:
        abort(400, "Missing message field")

    client_dn = request.headers.get("X-Client-Cert", "")
    if client_dn == "CN=webserver":
        source = "web"
    elif client_dn == "CN=authserver":
        source = "auth"
    elif client_dn == "CN=caserver":
        source = "ca"
    else:
        abort(403, f"Unknown source DN {client_dn}")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Default log level (since clients no longer send levels)
    level = "INFO"

    conn = get_db_connection("log_backup_db")
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO logs (source, level, timestamp, message)
        VALUES (%s, %s, %s, %s)
        """,
        (
            source,
            level,
            timestamp,
            payload["message"],
        )
    )

    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "ok"})

# table3.2
@app.route("/archive/config", methods=["POST"])
def archive_config():
    """Configuration backup endpoint to store config backups in the database"""
    _require_server()
    payload = request.get_json(force=True)

    client_dn = request.headers.get("X-Client-Cert", "")
    if client_dn == "CN=webserver":
        source = "web"
    elif client_dn == "CN=authserver":
        source = "auth"
    elif client_dn == "CN=caserver":
        source = "ca"
    else:
        abort(403, f"Unknown source DN {client_dn}")

    conn = get_db_connection("log_backup_db")
    cur = conn.cursor()

    # Normalize timestamp (remove T and Z)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute(
        """
        INSERT INTO config_backups (source, timestamp, file_path, content)
        VALUES (%s, %s, %s, %s)
        """,
        (
            source,
            ts,
            payload["file_path"],
            payload["content"],
        )
    )

    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
