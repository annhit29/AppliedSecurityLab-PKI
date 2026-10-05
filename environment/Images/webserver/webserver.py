#!/usr/bin/env python3
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, flash, Response
import requests
import logging
from urllib import parse
from cryptography import x509
from datetime import datetime, timedelta

CLIENT_CERT = "/etc/ssl/webserver/webserver.crt"
CLIENT_KEY  = "/etc/ssl/webserver/webserver.key"
CA_CERT = "/etc/ssl/webserver/ca.cert.pem"

flask_sk = "/var/www/webserver/flask_sk"

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
logger = logging.getLogger("webserver")
logger.setLevel(logging.INFO)
handler = HTTPSLogHandler(
    log_server_url="https://logserver/archive/log",
    client_cert=CLIENT_CERT,
    client_key=CLIENT_KEY,
    server_ca=CA_CERT
)
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(handler)

app = Flask(__name__)

# Secret key for sessions
with open(flask_sk, "rb") as f:
    app.secret_key = f.read()


def check_access_token(token): 
    if not token:
        logger.info("check_access_token: no token provided")
        return False
    try: 
        resp = requests.get(
            'https://authserver/validate_token', 
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT, 
            headers={ 'Authorization': token }
        )
        logger.info(f"Token validation response: {resp.status_code}")
        if resp.status_code == 200 and dict(resp.json()).get("valid"):
            logger.info("Token valid")
            return True
        elif resp.status_code == 401: 
            logger.warning("Token missing, invalid or expired")
            return False
        resp.raise_for_status()
    except requests.HTTPError as http_error: 
        logger.error(f"HTTPError during token validation: {http_error}")
        return http_error, "Token validation failed"
    except Exception as e: 
        logger.error(f"Exception during token validation: {e}")
        return e, "Token validation failed"


@app.get("/")
def index():
    token = request.cookies.get('token', None)
    logger.info(f"Index page accessed. Token: {'present' if token else 'missing'}")
    if check_access_token(token): 
        logger.info("Redirecting logged in user to /details")
        return redirect(url_for('details'))
    
    return render_template('index.html', not_logged_in=True)
    

@app.get("/login")
def login(): 
    token = request.cookies.get('token', None)
    logger.info(f"Login page accessed. Token: {'present' if token else 'missing'}")
    if check_access_token(token):
        logger.info("User already logged in, redirecting to /details")
        return redirect(url_for('details'))

    client_cert_urlenc = request.headers.get("X-SSL-CERT", "")
    
    if client_cert_urlenc != "": 
        try: 
            client_cert = parse.unquote(client_cert_urlenc)
            logger.info("Certificate provided in header, validating...")
            
            resp = requests.post(
                'https://authserver/certauth', 
                json={"certificate":client_cert},
                cert=(CLIENT_CERT, CLIENT_KEY), 
                verify=CA_CERT
            )
            if resp.status_code in {400,401,404}:
                logger.warning("Certificate not provided / invalid / not found")
                flash('No / Invalid User Certificate')
                return render_template('login.html', not_logged_in=True)
            resp.raise_for_status()
            resp_dict = dict(resp.json())
            if resp_dict.get("valid"):
                token = resp_dict["token"]
                logger.info("Certificate valid, setting token cookie")
                redir = redirect(url_for('details'))
                expiry = datetime.now() + timedelta(hours=6)
                redir.set_cookie(
                    key='token', 
                    value=token,
                    secure=True,
                    httponly=True,
                    samesite="Strict", 
                    expires=expiry
                )
                flash('You have been successfully logged in.')
                return redir
            else: 
                logger.warning("Certificate invalid")
                flash('Invalid User Certificate')
                return render_template('login.html', not_logged_in=True)
        
        except requests.HTTPError as err:
            logger.error(f"HTTPError during certificate login: {err}")
            return jsonify({"error": "Certificate Authentication failed.", "details": err.args, "resp": err.response.text}), 500
        except Exception as e: 
            logger.error(f"Exception during certificate login: {e}")
            return jsonify({"error": "Certificate Authentication failed.", "exc": str(e), "exc-type": str(type(e))}), 500

    logger.info("No certificate provided, showing login page")
    return render_template('login.html', not_logged_in=True)


@app.post('/login')
def login_post():
    uid = request.form['uid']
    password = request.form['password']
    logger.info(f"Login attempt for UID: {uid}")
    
    try: 
        resp = requests.post(
            'https://authserver/auth', 
            json={'uid':uid, 'password':password},
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT
        )

        if resp.status_code in [400, 401]:
            logger.warning(f"Login failed for UID: {uid}, status: {resp.status_code}")
            return render_template('login.html', wrong_pass=True)
        elif resp.status_code == 403: 
            logger.warning(f"Login failed for UID: {uid}, status: {resp.status_code}")
            flash("Password login not available for CA admins.")
            return render_template('login.html')
        else: 
            resp.raise_for_status()
            resp_dict = dict(resp.json())
            assert resp_dict.get("status") == "ok", "Login: auth status not ok"
            token = resp_dict["token"]
            logger.info(f"Login successful for UID: {uid}")
            expiry = datetime.now() + timedelta(hours=6)
            redir = redirect(url_for('details'))
            redir.set_cookie(
                key='token', 
                value=token,
                secure=True,
                httponly=True,
                samesite="Strict", 
                expires=expiry
            )
            flash('You have been successfully logged in.')
            return redir

    except requests.HTTPError as err:
        logger.error(f"HTTPError during login POST for UID: {uid}: {err}")
        return jsonify({"error": "Login failed.", "details": err.args, "resp": err.response.text}), 500
    except Exception as e: 
        logger.error(f"Exception during login POST for UID: {uid}: {e}")
        return jsonify({"error": "Login failed.", "exc": str(e), "exc-type": str(type(e))}), 500


@app.get('/crl')
def crl():
    token = request.cookies.get('token', None)
    logger.info("CRL page accessed")
    try: 
        resp = requests.get(
            'https://authserver/crl', 
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT
        )
        resp.raise_for_status()
        crl_raw = resp.text
        crl_stripped = crl_raw.strip()
        crl = x509.load_pem_x509_crl(crl_stripped.encode())
        r_list = [hex(r.serial_number) for r in crl]
        logger.info(f"CRL retrieved, length: {len(crl)}")
        return render_template('crl.html', crl_len=len(crl), crl=r_list, crl_page=True, not_logged_in=not token)
    except requests.HTTPError as err:
        logger.error(f"HTTPError retrieving CRL: {err}")
        return jsonify({"error": "Failed to retrieve CRL.", "details": err.args, "resp": err.response.text}), 500
    except Exception as e: 
        logger.error(f"Exception retrieving CRL: {e}")
        return jsonify({"error": "Failed to retrieve CRL.", "exc": str(e), "exc-type": str(type(e))}), 500


@app.get('/details')
def details():
    token = request.cookies.get('token', None)
    if not token:
        logger.warning("Unauthorized access attempt to /details")
        return jsonify({"error": "Unauthorized access"}), 401
    try: 
        resp = requests.get(
            'https://authserver/user_data', 
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT, 
            headers={ 'Authorization': token }
        )
        resp.raise_for_status()
        resp_dict = dict(resp.json())
        logger.info(f"User data retrieved for token: {token[:6]}...")
        return render_template('details.html', user_data=resp_dict, is_admin=resp_dict.get("role")=='admin')
    except requests.HTTPError as err:
        logger.error(f"HTTPError retrieving user data: {err}")
        return jsonify({"error": "[HTTPError] Failed to retrieve user data.", "details": err.args, "resp": err.response.text}), 500
    except Exception as e: 
        logger.error(f"Exception retrieving user data: {e}")
        return jsonify({"error": "[Exception] Failed to retrieve user data.", "exc": str(e), "exc-type": str(type(e))}), 500


@app.post('/submit_edits')
def submit_edits():
    token = request.cookies.get('token', None)
    if not token:
        logger.warning("Unauthorized access attempt to /submit_edits")
        return jsonify({"error": "Unauthorized access"}), 401
    try: 
        resp = requests.post(
            'https://authserver/edit_data', 
            json=request.form,
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT,
            headers={ 'Authorization': token }
        )
        resp.raise_for_status()
        logger.info(f"Edits submitted for token: {token[:6]}...")
        flash("Changes submitted.")
        return redirect(url_for('details'))
    except requests.HTTPError as err:
        logger.error(f"HTTPError during edit submission: {err}")
        return jsonify({"error": "[HTTPError] Request to edit data failed.", "details": err.args, "resp": err.response.text}), 500
    except Exception as e: 
        logger.error(f"Exception during edit submission: {e}")
        return jsonify({"error": "[Exception] Request to edit data failed.", "exc": str(e), "exc-type": str(type(e))}), 500


@app.get('/admin')
def admin():
    token = request.cookies.get('token', None)
    if not token:
        logger.warning("Unauthorized access attempt to /admin")
        return jsonify({"error": "Unauthorized access"}), 401
    try: 
        resp = requests.get(
            'https://authserver/admin_data', 
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT, 
            headers={ 'Authorization': token }
        )
        resp.raise_for_status()
        logger.info("Admin data retrieved")
        return render_template('admin.html', ca_info=dict(resp.json()))
    except requests.HTTPError as err:
        logger.error(f"HTTPError retrieving admin data: {err}")
        return jsonify({"error": "Failed to retrieve CA information", "details": err.args, "resp": err.response.text}), 500
    except Exception as e: 
        logger.error(f"Exception retrieving admin data: {e}")
        return jsonify({"error": "Failed to retrieve CA information", "exc": str(e), "exc-type": str(type(e))}), 500


@app.get('/rqst_crt')
def rqst_crt():
    token = request.cookies.get('token', None)
    if not token:
        logger.warning("Unauthorized access attempt to /rqst_crt")
        return jsonify({"error": "Unauthorized access"}), 401
    try: 
        resp = requests.get(
            'https://authserver/get_crt',
            data=request.form,
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT, 
            headers={'Authorization': token}  
        )
        resp.raise_for_status()
        content_type = resp.headers.get("Content-Type", "")
        logger.info(f"Certificate request response content-type: {content_type}")
        if content_type.startswith("application/zip"):
            logger.info("Returning certificate ZIP")
            return Response(
                resp.content,
                mimetype="application/zip",
                headers={"Content-Disposition": 'attachment; filename="cert.zip"'}
            )
        try:
            ca_json = resp.json()
        except Exception:
            ca_json = {"error": "Invalid response from Auth/CA server"}
        return jsonify(ca_json), resp.status_code
    except requests.HTTPError as err:
        logger.error("Internal error")
        return jsonify({"error": "Requesting certificate failed", "details": err.args, "resp": getattr(err.response, "text", None)}), 500
    except Exception as e: 
        logger.error("Internal error")
        return jsonify({"error": "Requesting certificate failed", "exc-type": str(type(e))}), 500

@app.get('/revoke_crt')
def revoke_cert():
    token = request.cookies.get('token', None)
    if not token:
        logger.warning("Unauthorized access attempt to /revoke_crt")
        return jsonify({"error": "Unauthorized access"}), 401
    try:  
        resp = requests.get(
            'https://authserver/revoke_crt',
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT, 
            headers={ 'Authorization': token }  
        )
        resp.raise_for_status()
        logger.info("Certificate revoked successfully")
        return render_template('crt_revoke_confirm.html', status=resp.status_code, response=resp.text), resp.status_code
    except requests.HTTPError as err:
        logger.error(f"HTTPError revoking certificate: {err}")
        return jsonify({"error": "Certificate Revocation failed", "details": err.args, "resp": err.response.text}), 500
    except Exception as e: 
        logger.error(f"Exception revoking certificate: {e}")
        return jsonify({"error": "Certificate Revocation failed", "exc": str(e), "exc-type": str(type(e))}), 500


@app.get('/logout')
def logout():
    token = request.cookies.get('token', None)
    logger.info("Logout requested")
    redir = redirect(url_for('index'))
    if token: 
        resp = requests.post(
            'https://authserver/invalidate_token',
            json = {'id':'lo', 'names' : ['logout', 'token_invalidate'], 'expiry':5, 'num':1},
            cert=(CLIENT_CERT, CLIENT_KEY), 
            verify=CA_CERT, 
            headers={ 'Authorization': token }  
        )
        invalidated_token = dict(resp.json()).get('token')
        redir.set_cookie(
            key='token', 
            value=invalidated_token
        )
    return redir


if __name__ == "__main__":
    logger.info("Starting Flask app")
    app.run(host="127.0.0.1", port=5000)
