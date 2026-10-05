#!/usr/bin/env python3
from flask import Flask, request, jsonify, Response
import os
import socket
import requests
import hashlib
import mysql.connector # type: ignore
import jwt # type: ignore
import datetime
import logging
import re


CA_CERT="/etc/ssl/authserver/ca.cert.pem"
CLIENT_CERT="/etc/ssl/authserver/authserver.crt"
CLIENT_KEY="/etc/ssl/authserver/authserver.key"

SECRET_KEY = os.environ["JWT_SECRET"]
BACKUP_SERVER_URL = os.environ.get("BACKUP_SERVER_URL", "https://logserver/archive/log")

DB_HOST = "localhost" # MySQL is running inside authserver
DB_NAME = "imovies" # matches the imported dump
DB_USER = "authserver"
DB_PASS = os.environ["AUTH_DB_PASSWORD"]

UID_PATTERN = re.compile(r"^[a-z0-9]{1,32}$")   # lowercase alphanumeric, max length 32 UIDs

app = Flask(__name__)

def send_user_backup(user):
    """
    Send the current state of a user row to the logserver
    so it can store a snapshot in userdb_backup_db.user_snapshots.
    """
    try:
        requests.post(
            "https://logserver/archive/userdb",
            json={
                "uid": user["uid"],
                "lastname": user["lastname"],
                "firstname": user["firstname"],
                "email": user["email"],
                "pwd_hash": user["password_sha256"],
            },
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
            timeout=3
        )
    except Exception as e:
        logger.error(f"userdb_backup_failed: {e}")

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
                timeout=3
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send log: {e}")

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
logger = logging.getLogger("authserver")
handler = HTTPSLogHandler(
    log_server_url=BACKUP_SERVER_URL,
    client_cert=CLIENT_CERT,
    client_key=CLIENT_KEY,
    server_ca=CA_CERT
)
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(handler)

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except socket.herror:
        hostname = ip
    return hostname

def db_connect():
    # Nur read und update erlaubt
    # TODO: MYSQL IS NEVER STARTED?
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

def authenticate_user(uid, password): ## check if user is not admin
    conn = db_connect()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT uid, lastname, firstname, email, password_sha256, role FROM users WHERE uid = %s",
        (uid,)
    )

    user = cursor.fetchone()
    conn.close()
    if user:
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if pwd_hash == user['password_sha256']:
            send_user_backup(user) # send snapshot to logserver when user logs in successfully
            return user
    return None

def generate_token(user, serial = None):
    payload = {
        
        "uid": user["uid"],
        #"email": user["email"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),
        "user": {
            "firstname": user["firstname"],
            "lastname": user["lastname"]
        },
        "serial": serial, # Only set if authenticating using a certificate, otherwise None
        "role": user["role"]  ##encode admin/user rights
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


@app.route("/auth", methods=["POST"])
def auth():
    sender_ip = request.remote_addr
    hostname = get_hostname(sender_ip)

    # -------- JSON VALIDATION ----------
    try:
        # Only parse JSON if Content-Type is application/json
        data = request.get_json(force=False, silent=False)
    except Exception:
        logger.warning(f"auth_failed - invalid JSON from {sender_ip}")
        return jsonify({"status": "error", "msg": "Invalid JSON"}), 400

    if not isinstance(data, dict): # ensure it is a JSON object but not other types
        return jsonify({"status": "error", "msg": "Invalid request format"}), 400

    # Only allow specific fields, i.e. "uid" and "password" fields (no other fields allowed)
    allowed_keys = {"uid", "password"}
    if set(data.keys()) != allowed_keys:
        logger.warning(f"auth_failed - unexpected fields from {sender_ip}")
        return jsonify({"status": "error", "msg": "Invalid fields"}), 400

    uid = data.get("uid")
    password = data.get("password")

    # ------ TYPE VALIDATION (only allow strings) -----------
    if not isinstance(uid, str) or not isinstance(password, str):
        return jsonify({"status": "error", "msg": "Invalid types"}), 400

    # ------ CONTENT VALIDATION --------
    if not UID_PATTERN.match(uid):
        return jsonify({"status": "error", "msg": "Invalid UID format"}), 400

    if len(password) == 0 or len(password) > 128:
        return jsonify({"status": "error", "msg": "Invalid password length"}), 400

    # -------- AUTHENTICATION ----------
    try:
        user = authenticate_user(uid, password)
    except Exception as e:
        logger.error(f"auth_error - internal error for uid={uid}: {e}")
        return jsonify({"status": "error", "msg": "Internal error"}), 500

    # -------- RESPONSE ----------
    if user:
        if user.get("role") == 'admin': 
            logger.warning(f"auth_failed - admin logging in with uid/pwd from {sender_ip}")
            return jsonify({"status": "error", "msg": "Admin without certificate"}), 403
        else: # normal user
            token = generate_token(user)
            logger.info(f"auth_success - user {uid} from {sender_ip}")
            return jsonify({"status": "ok", "token": token, "server": hostname}), 200
    else:
        logger.warning(f"auth_failed - wrong credentials from {sender_ip}")
        return jsonify({"status": "error", "msg": "Authentication failed"}), 401

@app.route("/invalidate_token", methods=["POST"])
def invalidate_token():
    sender_ip = request.remote_addr
    hostname = get_hostname(sender_ip)
    token = request.headers.get("Authorization")
    try:
        # Only parse JSON if Content-Type is application/json
        data = request.get_json(force=False, silent=False)
    except Exception:
        logger.warning(f"invalidate token failed - invalid JSON from {sender_ip}")
        return jsonify({"status": "error", "msg": "Invalid JSON"}), 400

    uid = data["id"]
    prefix = uid[0]
    serial = data["num"]
    user = {
        'uid' : uid, 
        'firstname' : data["names"][0],
        'lastname': data["names"][1],
        'expiry' : data["expiry"],
        'serial': serial
    }

    checked_user = user_authenticate(user, token)

    raw_token = generate_token(user=checked_user, serial=serial)
    token = "".join([prefix,raw_token])
    return jsonify({"status": "ok", "token": token, "server": hostname}), 200
    

@app.route("/certauth", methods=["POST"])
def cert_auth():
    # Zertifikatsbasierte Authentifizierung, ggf. Weiterleitung an CA Server

    ## admins dürfen sich nur mit Zertifikat einloggen, admin rolle spielt bei uid/pw keine Rolle 
    sender_ip = request.remote_addr
    cert_data = request.get_json(force=True).get("certificate")
    if not cert_data:
        logger.warning(f"certauth_failed - no certificate provided from {sender_ip}")
        return jsonify({"valid": False, "msg": "Certificate missing"}), 400

    try:
        ca_resp = requests.post(
            "https://caserver/validate", 
            json={"certificate": cert_data},
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
            timeout=3
        )
        valid = ca_resp.json().get("valid", False)
        user_id = ca_resp.json().get("uid")
        serial = ca_resp.json().get("serial", None)
        logger.info(f"certauth_attempt - certificate from {sender_ip}: valid={valid}")
        #result = {"valid": valid, "ca_admin": ca_resp.json().get("ca_admin", False)}
        #return jsonify(result), 200
        if not valid or not user_id:
            return jsonify({"valid": False, "msg": "Certificate invalid or no uid info"}), 401
    
        conn = db_connect()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT uid, firstname, lastname, role FROM users WHERE uid = %s", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if not user:
            logger.warning(f"certauth_failed - user for certificate not found: {user_id}")
            return jsonify({"valid": False, "msg": "No user found"}), 404

        token = generate_token({
            "uid": user["uid"],
            "firstname": user["firstname"],
            "lastname": user["lastname"],
            "role": user["role"]
        }, serial=serial)
        return jsonify({
            "valid": True,
            "token": token,
            "role": user["role"],
            "firstname": user["firstname"],
            "lastname": user["lastname"]
        }), 200
    except Exception as e:
        logger.error(f"certauth_error - CA server unreachable: {str(e)} from {sender_ip}")
        return jsonify({"valid": False, "msg": "CA Server error"}), 502


@app.route("/validate_token", methods=["GET"])
def validate_token():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "missing token "}), 401
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"status": "ok", "valid": True}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.exceptions.InvalidTokenError: 
        return jsonify({"error": "Token invalid"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400




def user_authenticate(user, token):
    # Check for user in database
    conn = db_connect()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT uid, lastname, firstname, email, password_sha256, role FROM users WHERE uid = %s",
        (user["uid"],)
    )
    fetched = cursor.fetchone()
    conn.close()

    # Check token validity
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    ##jwt.decode checks automatically if token valid (valid signature) and not expired
    user_id = payload.get("uid") 

    if (not 'admin' in payload or not 'admin' in fetched) and user_id == user["uid"]: 
        user['role'] = 'user'   
    user["uid"] = payload.get("uid") 
    # Fill in missing information
    user["email"] = payload.get("email")
    user['role'] = 'admin'
    return user


@app.route("/crl", methods=["GET"])
def crl(): 
    resp = None
    try:
        resp = requests.get(
            'https://caserver/crl', 
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT,
            timeout=5
        )
        resp.raise_for_status()
        return resp.text, resp.status_code
    except requests.HTTPError as err: 
        # logger.error(f"crl_error - {str(err)}") TODO
        return f"Error on calling certificate, resp = {resp.text if resp else ''}", 500
    except Exception as e:
        logger.error(f"crl_error - {str(e)}")
        return f"Error on calling certificate, resp = {resp.text if resp else ''}", 500


@app.get('/user_data')
def user_data():
    # Get Actual User Data from Data Base
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "missing token "}), 401
  
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        ##jwt.decode checks automatically if token valid (valid signature) and not expired
        user_id = payload.get("uid") 
        #user_role = payload.get("role")
        # get user-data and role from db
        conn = db_connect()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT uid, lastname, firstname, email,  role FROM users WHERE uid = %s", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            # user data and role
            return jsonify({
                "uid": user["uid"],
                "firstname": user["firstname"],
                "lastname": user["lastname"],
                "email": user["email"],
                "role": user["role"]
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400


def get_jwt_identity(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("uid")
    except Exception:
        return None


@app.post('/edit_data')
def edit_data():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Missing Token"}), 401
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("uid")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    allowed_fields = ["firstname", "lastname", "email"]
    update_values = {field: data[field] for field in allowed_fields if field in data}

    # Password-Update: 'password' is not a field in update_values, it gets hashed and stored as password_sha256
    if "password" in data and data["password"]:
        import hashlib
        pwd_hash = hashlib.sha256(data["password"].encode("utf-8")).hexdigest()
        update_values["password_sha256"] = pwd_hash

    if not update_values:
        return jsonify({"error": "no valid fields given to update"}), 400

    set_clause = ', '.join([f"{field} = %s" for field in update_values.keys()])
    params = list(update_values.values()) + [user_id]  # fields followed by uid

    try:
        conn = db_connect()
        cursor = conn.cursor(dictionary=True) # use dict cursor to easily build JSON
        sql = f"UPDATE users SET {set_clause} WHERE uid = %s"
        cursor.execute(sql, params)
        conn.commit()
        
        cursor.execute(
            "SELECT uid, lastname, firstname, email, password_sha256 FROM users WHERE uid = %s",
            (user_id,),
        )

        updated_user = cursor.fetchone()

        conn.close()

        updated_keys = list(update_values.keys())
        # for the client feedback just show 'password' 
        if "password_sha256" in updated_keys:
            updated_keys = [k if k != "password_sha256" else "password" for k in updated_keys]

        # send snapshot to logserver
        if updated_user:
            send_user_backup(updated_user)
        else:
            logger.warning(f"userdb_backup_skipped - user {user_id} not found after update")

        logger.info(f"edit_success - user {user_id} updated fields: {updated_keys}")
        return jsonify({"status": "ok", "updated_fields": updated_keys}), 200
    except Exception as e:
        logger.error(f"edit_failed - user {user_id} failed to update: {str(e)}")
        return jsonify({"error": "database error"}), 500


def get_jwt_payload(token):
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception:
        return None
    
@app.get('/admin_data')
def admin_data(): 
    auth_header = request.headers.get("Authorization")
    payload = get_jwt_payload(auth_header)

    if not payload:
        return jsonify({"error": "Invalid or missing Token"}), 401

    # check on admin rights
    
    if payload.get("role") != "admin":
        return jsonify({"error": "No admin rights"}), 403

    # request to the CA-server
    try:
        resp = requests.get(
            'https://caserver/ca_info', 
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT
        )
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
  


@app.get('/get_crt')
def get_crt():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Token missing"}), 401
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("uid")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    try:
        ca_response = requests.post(
            "https://caserver/issue",
            json={ "cn": user_id },
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
            timeout=5
        )
        content_type = ca_response.headers.get("Content-Type", "")

        if content_type.startswith("application/zip"):
            # Successful issuance: return the ZIP
            logger.info(f"certificate_request - user {user_id} requested certificate successfully")
            return Response(
                ca_response.content,
                mimetype="application/zip",
                headers={"Content-Disposition": f'attachment; filename="{user_id}.zip"'}
            )

        # Otherwise assume JSON error
        logger.error(f"certificate_request_failed - error for UID {user_id}: could not return certificate")
        try:
            ca_json = ca_response.json()
        except Exception:
            ca_json = {"error": "Invalid response from CA"}
        return jsonify(ca_json), ca_response.status_code

    except Exception as e:
        logger.error(f"certificate_request_failed - error for UID {user_id}: {str(e)}")
        return jsonify({"error": "CA Server Error"}), 502

    

@app.get('/revoke_crt')
def revoke_crt():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Missing token"}), 401
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("uid")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400


    serial = payload.get("serial")
    uid = payload.get("uid")
    if serial: 
        data = {"serial" : serial}
    else: 
        data = {"cn" : uid}

    try:
        ca_response = requests.post(
            "https://caserver/revoke",
            json=data,
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
            timeout=5
        )
        ca_json = ca_response.json()
        logger.info(f"certificate_revocation - user {user_id} revoked certificate: {serial if serial else uid} -- CA: {ca_json}")
        return jsonify(ca_json), ca_response.status_code
    except Exception as e:
        logger.error(f"certificate_revocation_failed - error for UID {user_id}: {str(e)}")
        return jsonify("Error"), 400
    
@app.post('/download_certificate')
def download_certificate():
    # check token
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "missing Token"}), 401
    token = auth_header[7:] if auth_header.startswith("Bearer ") else auth_header

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("uid")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    # check attributes
    try:
        req_data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    
    try:
        ca_response = requests.post(
            "https://caserver/issue",
            json={
                "cn": user_id,
            },
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
            timeout=5
        )
        if ca_response.status_code != 200:
            logger.error(f"download_certificate_failed - user {user_id}, CA response: {ca_response.text}")
            return jsonify({"error": "CA Server Error"}), ca_response.status_code

        
        ca_json = ca_response.json()
        logger.info(f"download_certificate - user {user_id}: certificate loaded")
        return jsonify(ca_json), 200
    except Exception as e:
       logger.error(f"download_certificate_failed - user {user_id}, error: {str(e)}")
    return jsonify({"error": "CA Server Fehler"}), 502



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
