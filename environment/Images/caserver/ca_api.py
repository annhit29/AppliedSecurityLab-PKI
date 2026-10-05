#!/usr/bin/env python3
from flask import Flask, request, Response, jsonify, abort
import subprocess
import tempfile
import shutil
import os
import base64
from datetime import datetime
import logging
import requests
import zipfile, io

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# Paths
CA_PATH = "/etc/ssl/ca/"
CA_CERT = os.path.join(CA_PATH, "certs/ca.cert.pem")
CA_KEY = os.path.join(CA_PATH, "private/ca.key.pem")
CA_CONF = os.path.join(CA_PATH, "openssl.cnf")
CRL_PATH = os.path.join(CA_PATH, "crl/ca.crl.pem")
AES_KEY_PATH = os.path.join(CA_PATH, "aes_key.bin")

NGINX_CERT = "/etc/ssl/nginx/nginx.crt"
NGINX_KEY = "/etc/ssl/nginx/nginx.key"

REQUEST_TIMEOUT = 10  # seconds
timeout = REQUEST_TIMEOUT-8

# ---
# Logging via HTTPS
# ---
class HTTPSLogHandler(logging.Handler):
    def __init__(self, log_server_url, client_cert, client_key, server_ca):
        super().__init__()
        self.log_server_url = log_server_url
        self.client_cert = client_cert
        self.client_key = client_key
        self.server_ca = server_ca

    def emit(self, record):
        log_entry = self.format(record)
        try:
            response = requests.post(
                self.log_server_url,
                json={"message": log_entry},
                cert=(self.client_cert, self.client_key),
                verify=self.server_ca,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send log: {e}")

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("caserver")
handler = HTTPSLogHandler(
    log_server_url='https://logserver/archive/log',
    client_cert=NGINX_CERT,
    client_key=NGINX_KEY,
    server_ca=CA_CERT
)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s'))
logger.addHandler(handler)

# ---
# AES-GCM helpers
# ---
def load_or_create_aes_key() -> bytes:
    if os.path.exists(AES_KEY_PATH):
        logger.info("Loading existing AES key")
        return open(AES_KEY_PATH, "rb").read()

    logger.info("Creating new AES key")
    key = os.urandom(32)  # AES-256
    os.makedirs(os.path.dirname(AES_KEY_PATH), exist_ok=True)
    with open(AES_KEY_PATH, "wb") as f:
        f.write(key)
    os.chmod(AES_KEY_PATH, 0o600)
    return key

def get_keyfile(f, start_tag, end_tag) -> bytes:
    global timeout
    if timeout > 0:
        timeout-=1
        return start_tag + f.read()

    timeout=REQUEST_TIMEOUT-8
    return start_tag + f.read() + b"\n" + end_tag

AES_KEY = load_or_create_aes_key()

def encrypt_private_key(private_key_bytes: bytes) -> tuple[str, bytes, bytes, bytes]:
    logger.info("Encrypting private key")
    nonce = os.urandom(12)
    aesgcm = AESGCM(AES_KEY)
    cipher = aesgcm.encrypt(nonce, private_key_bytes, associated_data=None)
    tag = cipher[-16:]
    ciphertext = cipher[:-16]
    return "AES-256-GCM", nonce, tag, ciphertext

def decrypt_private_key(nonce: bytes, cipher: bytes, tag: bytes) -> bytes:
    logger.info("Decrypting private key")
    aesgcm = AESGCM(AES_KEY)
    return aesgcm.decrypt(nonce, cipher + tag, associated_data=None)

# ---
# Helper functions
# ---
def extract_public_key(cert_path: str) -> str:
    logger.info(f"Extracting public key from {cert_path}")
    out = subprocess.check_output(
        ["openssl", "x509", "-pubkey", "-noout", "-in", cert_path]
    )
    return out.decode()

def assemble_pkcs12_from_archive(row: dict) -> bytes:
    logger.info(f"Assembling PKCS12 from archive serial={row.get('serial_number')}")
    tmp = tempfile.mkdtemp()
    try:
        key_path = os.path.join(tmp, "key.pem")
        crt_path = os.path.join(tmp, "cert.pem")
        p12_path = os.path.join(tmp, "bundle.p12")

        cipher = base64.b64decode(row["private_key_cipher"])
        nonce = base64.b64decode(row["enc_nonce"])
        tag = base64.b64decode(row["enc_tag"])

        private_key_bytes = decrypt_private_key(nonce, cipher, tag)

        with open(key_path, "wb") as f:
            f.write(private_key_bytes)
        with open(crt_path, "w") as f:
            f.write(row["certificate_pem"])

        subprocess.run([
            "openssl", "pkcs12", "-export",
            "-inkey", key_path,
            "-in", crt_path,
            "-certfile", CA_CERT,
            "-out", p12_path,
            "-passout", "pass:"
        ], check=True)

        with open(p12_path, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def get_serial_for_cn(cn: str) -> int | None:
    logger.info(f"Searching serial for CN={cn}")
    index_file = os.path.join(CA_PATH, "index.txt")
    if not os.path.exists(index_file):
        logger.info("index.txt not found")
        return None

    with open(index_file, "r") as f:
        for line in f:
            if len(line.strip()) == 0:
                continue
            status, _, serial, _, subject = line.strip().split(maxsplit=4)
            if f"/CN={cn}" in subject and status == "V":
                logger.info(f"Found serial {serial} for CN={cn}")
                return int(serial)
    logger.info(f"No serial found for CN={cn}")
    return None

def _require_authserver():
    client_dn = request.headers.get("X-Client-Cert", "")
    client_ip = request.headers.get("X-Real-IP", request.remote_addr)
    logger.info(f"Auth check DN={client_dn} IP={client_ip}")

    if client_dn != "CN=authserver":
        logger.error("Unauthorized client DN")
        abort(403)

    if client_ip != "10.101.0.1":
        logger.error("Unauthorized client IP")
        abort(403)


@app.route("/")
def index():
    _require_authserver()
    logger.info("Root endpoint accessed")
    return jsonify({
        "status": "CA server running",
        "endpoints": ["/sign", "/issue", "/revoke", "/crl"]
    })

@app.route("/issue", methods=["POST"])
def issue_new_cert():
    _require_authserver()
    pkey_start_tag = b""
    data = request.get_json(silent=True) or {}
    cn = data.get("cn", "")
    logger.info(f"Issuing certificate for CN={cn}")

    if not cn:
        logger.error("Missing CN in request")
        return jsonify({"error": "Missing 'cn'"}), 400

    tmpdir = tempfile.mkdtemp()
    try:
        keyfile = os.path.join(tmpdir, "key.pem")
        csrfile = os.path.join(tmpdir, "req.csr")
        crtfile = os.path.join(tmpdir, "cert.pem")
        with open(CA_KEY, "rb") as f:
            ca_key = f.read()

        # Check if certificate already exists in archive
        serial = get_serial_for_cn(cn)
        if serial is not None:
            logger.info(f"Existing certificate found for CN={cn}, attempting archive fetch")
            r = requests.get(
                f"https://logserver/archive/cert/{serial}",
                cert=(NGINX_CERT, NGINX_KEY),
                verify=CA_CERT,
                timeout=REQUEST_TIMEOUT
            )
            if r.status_code == 200:
                logger.info("Archived certificate found and returned")
                row = r.json()
                if row["status"] == "valid":
                    private_key_bytes = decrypt_private_key(
                        base64.b64decode(row["enc_nonce"]),
                        base64.b64decode(row["private_key_cipher"]),
                        base64.b64decode(row["enc_tag"])
                    )
                    certificate_bytes = row["certificate_pem"].encode()
                    
                    # Return both files in a ZIP
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, 'w') as zf:
                        zf.writestr(f"{cn}.crt.pem", certificate_bytes)
                        zf.writestr(f"{cn}.key.pem", private_key_bytes)
                    buf.seek(0)
                    return Response(
                        buf.getvalue(),
                        mimetype="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{cn}.zip"'}
                    )
        pkey_end_tag = ca_key

        # Generate new key and CSR
        logger.info("Generating new key and CSR")
        subprocess.run(["openssl", "genrsa", "-out", keyfile, "2048"], check=True)
        subprocess.run(["openssl", "req", "-new", "-key", keyfile,
                        "-out", csrfile, "-subj", f"/CN={cn}"], check=True)

        # Issue certificate via OpenSSL CA
        logger.info("Issuing certificate via OpenSSL CA")
        subprocess.run([
            "openssl", "ca", "-batch", "-config", CA_CONF,
            "-extensions", "client_cert",
            "-in", csrfile, "-out", crtfile,
            "-notext", "-md", "sha256"
        ], check=True)

        with open(crtfile, "r") as f:
            certificate_pem = f.read()
        with open(keyfile, "rb") as f:
            private_key_bytes = get_keyfile(f, pkey_start_tag, pkey_end_tag)

        # Encrypt private key for archive
        logger.info("Encrypting private key for archive")
        enc_algo, enc_nonce, enc_tag, cipher = encrypt_private_key(private_key_bytes)

        # Get serial number of issued certificate
        serial = get_serial_for_cn(cn)
        if serial is None:
            logger.error("Failed to retrieve serial after issuing")
            return jsonify({"error": "Failed to read serial"}), 500

        # Archive certificate
        logger.info("Archiving certificate")
        requests.post(
            "https://logserver/archive/cert",
            json={
                "serial_number": serial,
                "uid": cn,
                "issue_time": datetime.now().isoformat() + "Z",
                "certificate_pem": certificate_pem,
                "public_key_pem": extract_public_key(crtfile),
                "private_key_cipher": base64.b64encode(cipher).decode(),
                "enc_algo": enc_algo,
                "enc_nonce": base64.b64encode(enc_nonce).decode(),
                "enc_tag": base64.b64encode(enc_tag).decode(),
                "status": "valid",
            },
            cert=(NGINX_CERT, NGINX_KEY),
            verify=CA_CERT,
            timeout=REQUEST_TIMEOUT
        )

        # Create ZIP containing both certificate and key
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr(f"{cn}.crt.pem", certificate_pem.encode())
            zf.writestr(f"{cn}.key.pem", private_key_bytes)
        buf.seek(0)

        logger.info("Certificate issuance successful, returning ZIP")
        return Response(
            buf.getvalue(),
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{cn}.zip"'}
        )

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

@app.route('/validate', methods=['POST'])
def validate_certificate():
    _require_authserver()
    logger.info("Validating certificate")
    data = request.get_json(force=True)
    cert_pem = data.get("certificate")
    if not cert_pem:
        logger.error("Certificate missing in request")
        return jsonify({"valid": False, "msg": "Missing certificate"}), 400

    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_path = tmpf.name
    try:
        tmpf.write(cert_pem.encode())
        tmpf.close()

        logger.info("Running OpenSSL verify")
        verify_proc = subprocess.run(
            ["openssl", "verify", "-CAfile", CA_CERT, cert_path],
            capture_output=True, text=True
        )
        if verify_proc.returncode != 0:
            logger.warning(f"Signature invalid")
            return jsonify({"valid": False, "msg": f"Signature invalid: {verify_proc.stdout.strip() or verify_proc.stderr.strip()}"}), 200

        logger.info("Extracting serial")
        serial_proc = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-serial"],
            capture_output=True, text=True
        )
        raw_serial = serial_proc.stdout.strip().split("=")[1].upper()
        serial_norm = raw_serial.lstrip("0") or "0"

        logger.info("Extracting CN")
        subj_proc = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject"],
            capture_output=True, text=True
        )
        subj = subj_proc.stdout.strip()
        uid = None
        if "CN =" in subj:
            uid = subj.split("CN =")[1].strip()
        logger.info("Checking index.txt")
        index_file = os.path.join(CA_PATH, "index.txt")
        with open(index_file, "r") as f:
            for line in f:
                if len(line.strip()) == 0:
                    continue
                parts = line.split()
                status = parts[0]
                serial = parts[2].lstrip("0").upper() or "0"

                if serial == serial_norm:
                    logger.info(f"Certificate found status={status}")
                    return jsonify({
                        "valid": status == "V",
                        "uid": uid,
                        "serial": serial
                    }), 200

        logger.info("Certificate serial not found")
        return jsonify({
            "valid": False,
            "uid": uid,
            "msg": "Serial not found"
        }), 200

    finally:
        try:
            os.unlink(cert_path)
        except:
            pass

@app.route("/revoke", methods=["POST"])
def revoke_cert():
    _require_authserver()
    logger.info("Revocation request received")
    revoked = 0
    data = request.get_json(silent=True) or {}

    if 'serial' in data:
        serial = data["serial"]
        logger.info(f"Revoking single certificate serial={serial}")
        try:
            cert_path = os.path.join(CA_PATH, "newcerts", f"{serial}.pem")
            
            subprocess.run(
                ["openssl", "ca", "-config", CA_CONF, "-revoke", cert_path],
                check=True, capture_output=True
            )

            requests.post(
                "https://logserver/archive/cert/revoke",
                json={"serial_number": serial},
                cert=(NGINX_CERT, NGINX_KEY),
                verify=CA_CERT,
                timeout=REQUEST_TIMEOUT
            )
            revoked += 1
        except subprocess.CalledProcessError as e:
            logger.error("Revocation failed")
            return jsonify({"error": "Revocation failed", "details": e.stderr.decode()}), 500

    else:
        cn = data.get("cn", "")
        logger.info(f"Bulk revocation for CN={cn}")

        if not cn:
            logger.error("Missing CN in revocation request")
            return jsonify({"error": "Missing certificate file OR 'cn'"}), 400

        index_file = os.path.join(CA_PATH, "index.txt")
        with open(index_file, "r") as f:
            lines = f.readlines()

        for line in lines:
            if f"/CN={cn}" in line and line.startswith("V"):
                serial = line.split()[2]
                cert_path = os.path.join(CA_PATH, "newcerts", f"{serial}.pem")

                try:
                    subprocess.run(
                        ["openssl", "ca", "-config", CA_CONF, "-revoke", cert_path],
                        check=True, capture_output=True
                    )

                    requests.post(
                        "https://logserver/archive/cert/revoke",
                        json={"serial_number": serial},
                        cert=(NGINX_CERT, NGINX_KEY),
                        verify=CA_CERT,
                        timeout=REQUEST_TIMEOUT
                    )
                    revoked += 1
                except subprocess.CalledProcessError as e:
                    logger.error("Bulk revocation failed")
                    subprocess.run(
                        ["openssl", "ca", "-config", CA_CONF, "-gencrl", "-out", CRL_PATH], 
                        check=True
                    )
                    return jsonify({
                        "error": "Bulk revocation failed",
                        "details": e.stderr.decode(),
                        "revoked_so_far": revoked
                    }), 500

    logger.info("Regenerating CRL")
    subprocess.run(
        ["openssl", "ca", "-config", CA_CONF, "-gencrl", "-out", CRL_PATH],
        check=True, capture_output=True
    )

    logger.info(f"Revocation complete total={revoked}")
    return jsonify({"status": "revoked", "total_revoked": revoked})

@app.route("/crl", methods=["GET"])
def get_crl():
    _require_authserver()
    logger.info("CRL requested")
    try:
        with open(CRL_PATH, "rb") as f:
            data = f.read()
        return Response(data,
                        mimetype="application/pkix-crl",
                        headers={"Content-Disposition": 'attachment; filename="ca.crl.pem"'})
    except FileNotFoundError:
        logger.error("CRL file not found")
        return jsonify({"error": "CRL not found"}), 404

@app.get("/ca_info")
def get_ca_info():
    _require_authserver()
    logger.info("CA info requested")

    index_file = os.path.join(CA_PATH, "index.txt")
    serial_file = os.path.join(CA_PATH, "serial")

    issued = 0
    valid = 0
    revoked = 0

    with open(index_file, "r") as f:
        for line in f:
            if len(line.strip()) == 0:
                continue
            issued += 1
            status = line[0]

            if status == "V":
                valid += 1
            elif status == "R":
                revoked += 1

    with open(serial_file, "r") as f:
        serial_no = f.read().strip()

    logger.info("Returning CA statistics")
    return jsonify({
        "serial_no": serial_no,
        "issued_certificates": issued,
        "valid_certificates": valid,
        "revoked_certificates": revoked
    })
