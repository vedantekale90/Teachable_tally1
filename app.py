import time 
import os
from flask import Flask, render_template, request, jsonify
import requests
import json
import qrcode
import base64
from io import BytesIO
from functools import wraps
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# ============================================================
# 🔐 SECRET KEY (for future use)
# ============================================================

SECRET_API_KEY = os.getenv("SECRET_API_KEY")

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY")
        if api_key != SECRET_API_KEY:
            return jsonify({"error": "Unauthorized - Invalid API Key"}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# 🔧 CONFIGURATION
# ============================================================
BASE_URL = "https://apisandbox.whitebooks.in"
AUTH_URL = f"{BASE_URL}/einvoice/authenticate"
GSTN_URL = f"{BASE_URL}/einvoice/type/GSTNDETAILS/version/V1_03"
GENERATE_IRN_URL = f"{BASE_URL}/einvoice/type/GENERATE/version/V1_03"
GET_EINVOICE_URL = f"{BASE_URL}/einvoice/type/GETIRN/version/V1_03"

# Public GSTIN Verification API
PUBLIC_SEARCH_URL = f"{BASE_URL}/public/search"

# Sandbox credentials (use your test credentials)
#SANDBOX_EMAIL = "santoshp@logiangle.com"
SANDBOX_EMAIL = os.getenv("SANDBOX_EMAIL")
SANDBOX_USERNAME = os.getenv("SANDBOX_USERNAME")
SANDBOX_PASSWORD = os.getenv("SANDBOX_PASSWORD")
SANDBOX_CLIENT_ID = os.getenv("SANDBOX_CLIENT_ID")
SANDBOX_CLIENT_SECRET = os.getenv("SANDBOX_CLIENT_SECRET")

SANDBOX_HEADERS = {
    "username": SANDBOX_USERNAME,
    "password": SANDBOX_PASSWORD,
    "client_id": SANDBOX_CLIENT_ID,
    "client_secret": SANDBOX_CLIENT_SECRET,
}

# Public GST verification credentials (different client_id / secret)
# PUBLIC_CLIENT_ID = "GSTS9e0f6426-11f3-4136-9920-9c60b50e584c"
# PUBLIC_CLIENT_SECRET = "GSTS2cb2a023-8f95-4934-ba04-3ed84c5fb9f4"
PUBLIC_CLIENT_ID = os.getenv("PUBLIC_CLIENT_ID")
PUBLIC_CLIENT_SECRET = os.getenv("PUBLIC_CLIENT_SECRET")

# ============================================================
# 🕓 AUTH TOKEN CACHE (VALID 6 HOURS)
# ============================================================
auth_cache = {"token": None, "timestamp": 0}
TOKEN_VALIDITY = 1 * 60 * 60  # 6 hours

def get_auth_token(gstin):
    """Fetch AuthToken only if cache expired"""
    current_time = time.time()
    if auth_cache["token"] and (current_time - auth_cache["timestamp"] < TOKEN_VALIDITY):
        print("✅ Using cached AuthToken")
        return auth_cache["token"]

    print("🔄 Fetching new AuthToken...") 
    headers = SANDBOX_HEADERS.copy()
    headers["gstin"] = gstin

    try:
        # for counting api hits
        api_hit_counter["authenticate"] += 1
        # Try GET first (existing approach)
        auth_resp = requests.get(AUTH_URL, headers=headers, params={"email": SANDBOX_EMAIL}, timeout=10)
        print("🔸 AUTH STATUS:", auth_resp.status_code)
        print("🔸 AUTH RAW RESPONSE:", auth_resp.text)
        # print sanitized headers for debugging (mask secrets)
        headers_to_log = headers.copy()
        for k in ("password", "client_secret"):
            if k in headers_to_log:
                headers_to_log[k] = "****"
        print("🔸 AUTH REQ HEADERS:", headers_to_log)
        try:
            auth_data = auth_resp.json()
        except Exception as e:
            print("❌ Failed to parse auth JSON:", e)
            auth_data = None

        # Try multiple possible token locations
        token = None
        if auth_data:
            token = auth_data.get("data", {}).get("AuthToken") or auth_data.get("AuthToken") or auth_data.get("token") or auth_data.get("access_token") or auth_data.get("data", {}).get("token")

        # If no token from GET, try POST fallback (some APIs expect POST)
        if not token:
            try:
                print("🔁 Auth GET failed to return token; trying POST fallback...")
                post_payload = {
                    "username": SANDBOX_HEADERS.get("username"),
                    "password": SANDBOX_HEADERS.get("password"),
                    "client_id": SANDBOX_HEADERS.get("client_id"),
                    "client_secret": SANDBOX_HEADERS.get("client_secret"),
                    "gstin": gstin,
                    "email": SANDBOX_EMAIL
                }
                post_headers = {"Content-Type": "application/json"}
                post_resp = requests.post(AUTH_URL, json=post_payload, headers=post_headers, timeout=10)
                print("🔸 AUTH POST STATUS:", post_resp.status_code)
                print("🔸 AUTH POST RAW RESPONSE:", post_resp.text)
                try:
                    post_data = post_resp.json()
                except Exception as e:
                    print("❌ Failed to parse auth POST JSON:", e)
                    post_data = None

                if post_data:
                    token = post_data.get("data", {}).get("AuthToken") or post_data.get("AuthToken") or post_data.get("token") or post_data.get("access_token") or post_data.get("data", {}).get("token")
            except Exception as e:
                print("❌ Auth POST attempt failed:", e)

        if token:
            auth_cache["token"] = token
            auth_cache["timestamp"] = current_time
            print("✅ New AuthToken cached.")
            return token
        else:
            print("❌ AuthToken missing in response after GET and POST attempts.")
            return None
    except Exception as e:
        print("❌ Auth Error:", e)
        return None

# ============================================================
# 🏠 ROUTE 1: Home page (Frontend)
# ============================================================
@app.route('/')
def index():
    return render_template('index.html')


# ============================================================
# 🧾 ROUTE 2: Create E-Invoice (Full Flow)
# ============================================================
@app.route('/create_einvoice', methods=['POST'])
@require_api_key
def create_einvoice():
    try:
        payload = request.get_json()
        gstin = payload.get("gstin")
        invoice_data = payload.get("invoice_data")

        if not gstin:
            return jsonify({"error": "GSTIN is required"}), 400

        # ========================================================
        # STEP 1️⃣: AUTHENTICATION (uses cached token)
        # ========================================================
        token = get_auth_token(gstin)
        if not token:
            return jsonify({"error": "Unable to get valid AuthToken"}), 500
        print("✅ AuthToken:", token)

        # ========================================================
        # STEP 2️⃣: FETCH GSTN DETAILS
        # ========================================================
        print("\n🔹 STEP 2: FETCHING GSTN DETAILS...")
        gstn_headers = {
            **SANDBOX_HEADERS,
            "gstin": gstin,
            "auth-token": token
        }
        # for counting api hits
        api_hit_counter["verify_gstin"] += 1
        gstn_resp = requests.get(GSTN_URL, headers=gstn_headers, params={"param1": gstin, "email": SANDBOX_EMAIL})
        print("🔸 GSTN RAW RESPONSE:", gstn_resp.text)

        try:
            gstn_data = gstn_resp.json()
        except Exception as e:
            return jsonify({"error": "Invalid GSTN JSON", "raw": gstn_resp.text}), 500

        legal_name = gstn_data.get("data", {}).get("lgnm", "N/A")

        # ========================================================
        # STEP 3️⃣: GENERATE IRN
        # ========================================================
        print("\n🔹 STEP 3: GENERATING IRN...")
        irn_headers = {
            **SANDBOX_HEADERS,
            "gstin": gstin,
            "auth-token": token
        }

        invoice_json = invoice_data
        invoice_json["SellerDtls"]["Gstin"] = gstin

        # for counting api hits
        api_hit_counter["generate_irn"] += 1
        irn_resp = requests.post(GENERATE_IRN_URL, headers=irn_headers, params={"email": SANDBOX_EMAIL}, json=invoice_json)
        print("🔸 IRN RAW RESPONSE:", irn_resp.text)

        try:
            irn_data = irn_resp.json()
        except Exception as e:
            return jsonify({"error": "Invalid IRN JSON", "raw": irn_resp.text}), 500

        data_block = irn_data.get("data", {})
        irn = data_block.get("Irn", "")
        ack_no = data_block.get("AckNo", "")
        ack_dt = data_block.get("AckDt", "")
        signed_qr = data_block.get("SignedQRCode", "")
        signed_invoice = data_block.get("SignedInvoice", "")

        # Generate QR Code from Signed QR
        qr_img = qrcode.make(signed_qr)
        buffer = BytesIO()
        qr_img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        # ========================================================
        # STEP 4️⃣: GET E-INVOICE
        # ========================================================
        print("\n🔹 STEP 4: FETCHING E-INVOICE...")
        einvoice_headers = {
            **SANDBOX_HEADERS,
            "gstin": gstin,
            "auth-token": token
        }
        # for counting api hits
        api_hit_counter["get_einvoice"] += 1
        einvoice_resp = requests.get(GET_EINVOICE_URL, headers=einvoice_headers, params={"irn": irn})
        print("🔸 EINVOICE RAW RESPONSE:", einvoice_resp.text)

        try:
            einvoice_data = einvoice_resp.json()
        except Exception as e:
            einvoice_data = {"error": "Could not parse e-invoice JSON", "raw": einvoice_resp.text}

        # ========================================================
        # FINAL OUTPUT
        # ========================================================
        return jsonify({
            "legal_name": legal_name,
            "irn": irn,
            "ack_no": ack_no,
            "ack_dt": ack_dt,
            "signed_invoice": signed_invoice,
            "signed_qr": signed_qr,
            #"qr_code": qr_base64,
            "einvoice_data": einvoice_data
        })

    except Exception as e:
        print("❌ Exception:", str(e))
        return jsonify({"error": str(e)}), 500


# ============================================================
# 🧾 ROUTE 3: PUBLIC GSTIN VERIFICATION
# ============================================================
@app.route('/verify_gst', methods=['POST'])
@require_api_key
def verify_gst():
    try:
        data = request.get_json()
        gstin = data.get("gstin")

        if not gstin:
            return jsonify({"error": "GSTIN is required"}), 400

        headers = {"client_id": PUBLIC_CLIENT_ID, "client_secret": PUBLIC_CLIENT_SECRET}
        params = {"gstin": gstin, "email": SANDBOX_EMAIL}

        # for counting api hits
        api_hit_counter["verify_gst"] += 1
        resp = requests.get(PUBLIC_SEARCH_URL, headers=headers, params=params)
        print("🔹 PUBLIC SEARCH RAW RESPONSE:", resp.text)

        try:
            result = resp.json()
        except Exception:
            return jsonify({"error": "Invalid JSON from Whitebooks", "raw": resp.text})

        legal_name = result.get("data", {}).get("lgnm", "N/A")
        return jsonify({"legal_name": legal_name, "raw": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
# 🧾 ROUTE: Tally Integration API
# ============================================================
API2BOOKS_URL = "https://api.api2books.com/api/User/SalesWithInventory"
X_AUTH_KEY = os.getenv("X_AUTH_KEY")
@app.route('/test_api', methods=['POST'])
@require_api_key
def test_api():
    headers = {
        "X-Auth-Key": X_AUTH_KEY,
        "Template-Key": "1",
        "CompanyName": "Invoiso Private Limited",
        "AddAutoMaster": "1",
        "Automasterids": "1,2,3,4,5,6,7,8,9",
        "version": "3",
    }
    body = request.get_json(force=True)
    try:
        # for counting api hits
        api_hit_counter["test_api"] += 1
        response = requests.post(API2BOOKS_URL, json=body, headers=headers, timeout=30)
        try:
            api_response = response.json()
        except ValueError:
            api_response = response.text
        return jsonify({
            "status": response.status_code,
            "api_response": api_response
        }), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#============================================================
# 🧾 API HIT COUNTER
api_hit_counter = {
    "authenticate": 0,
    "verify_gstin": 0,
    "generate_irn": 0,
    "get_einvoice": 0,
    "verify_gst": 0,
    "test_api": 0
}
@app.route('/api_hits', methods=['GET'])
@require_api_key
def get_api_hits():
    return jsonify(api_hit_counter)


if __name__ == '__main__':
    app.run(debug=True)
