#!/usr/bin/env python3
"""
ATM Digital API Gateway v4 - JSON Database Version
Menggunakan JSON file sebagai database untuk menghindari SQLite issues
"""

from flask import Flask, request, jsonify
import os
import hashlib
import uuid
import datetime
import threading
import time
import functools
import json
import random
import re
#from argon2 import PasswordHasher
#from argon2.exceptions import VerifyMismatchError, InvalidHashError, VerificationError
#import secrets

# ==================== CONFIGURATION ====================
APP_NAME = os.environ.get("APP_NAME", "ATM Gateway v4 JSON")
DB_FILE = os.environ.get("DB_FILE", "atm_gateway_v4.json")
LOG_FILE = os.environ.get("LOG_FILE", "atm_log.txt")
ADMIN_TOKEN = os.environ.get("ATM_ADMIN_TOKEN", secrets.token_urlsafe(32))

# Security Config
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", 10 * 60))
FAILED_PIN_LIMIT = int(os.environ.get("FAILED_PIN_LIMIT", 3))
ACCOUNT_LOCK_SECONDS = int(os.environ.get("ACCOUNT_LOCK_SECONDS", 5 * 60))
MIN_WITHDRAWAL = int(os.environ.get("MIN_WITHDRAWAL", 50000))
WITHDRAWAL_MULTIPLE = int(os.environ.get("WITHDRAWAL_MULTIPLE", 50000))
TRANSFER_NETWORK_DELAY_MIN = float(os.environ.get("TRANSFER_NETWORK_DELAY_MIN", 1.0))
TRANSFER_NETWORK_DELAY_MAX = float(os.environ.get("TRANSFER_NETWORK_DELAY_MAX", 2.0))

# Investment Products
INVESTMENT_PRODUCTS = {
    "SAHAM_A": {"name": "Saham Blue Chip A", "risk": "medium", "min_amount": 100000, "return_rate": 0.15},
    "REKSADANA_B": {"name": "Reksadana Pasar Uang", "risk": "low", "min_amount": 50000, "return_rate": 0.08},
    "SBN_C": {"name": "Surat Berharga Negara", "risk": "low", "min_amount": 1000000, "return_rate": 0.06}
}

# Initialize Argon2 Password Hasher
try:
    ph = PasswordHasher(
        time_cost=2,
        memory_cost=102400,
        parallelism=2,
        hash_len=32,
        salt_len=16
    )
    ph.hash("test")
except Exception as e:
    print(f"Argon2 initialization failed: {e}")
    ph = None

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# ==================== UTILITY FUNCTIONS ====================
def log(level: str, msg: str, user: str = "system", ip: str = "unknown"):
    """Enhanced logging dengan level dan context"""
    timestamp = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    line = f"[{timestamp}] [{level}] [{user}] [{ip}] {msg}\n"
    print(line, end='')
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        print(f"Log write failed: {e}")

def audit_log(action: str, user: str, details: str, ip: str = "unknown"):
    """Khusus untuk log aktivitas penting/audit"""
    log("AUDIT", f"{action}: {details}", user, ip)

def hash_pin(pin: str) -> str:
    """Gunakan Argon2 untuk hashing PIN yang lebih aman dengan fallback ke SHA256"""
    if ph:
        try:
            return ph.hash(pin)
        except Exception as e:
            log("ERROR", f"Argon2 hashing failed: {e}, falling back to SHA256", "system")
    
    # Fallback to SHA256
    return hashlib.sha256(pin.encode()).hexdigest()

def verify_pin(pin: str, pin_hash: str) -> bool:
    """Verifikasi PIN dengan Argon2 atau SHA256 fallback"""
    if not pin or not pin_hash:
        return False
    
    # Try Argon2 first
    if ph and pin_hash.startswith("$argon2"):
        try:
            return ph.verify(pin_hash, pin)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            return False
        except Exception as e:
            log("ERROR", f"Argon2 verification error: {e}", "system")
            return False
    
    # Fallback to SHA256
    return pin_hash == hashlib.sha256(pin.encode()).hexdigest()

def validate_input(input_str: str, field_type: str, max_length: int = 100) -> bool:
    """Validasi input untuk mencegah injection dan abuse"""
    if input_str is None or len(str(input_str)) > max_length:
        return False
    
    input_str = str(input_str).strip()
    
    if field_type == 'numeric':
        return bool(re.match(r'^\d+$', input_str))
    elif field_type == 'name':
        # Terima nama dengan karakter internasional dan spasi
        return bool(re.match(r'^[a-zA-Z\s\.\-\'à-ÿÀ-ß]+$', input_str))
    elif field_type == 'pin':
        return bool(re.match(r'^\d{4,8}$', input_str))
    elif field_type == 'amount':
        return bool(re.match(r'^\d+(\.\d{1,2})?$', str(input_str)))
    elif field_type == 'rekening':
        return bool(re.match(r'^\d{10}$', input_str))
    elif field_type == 'token':
        return bool(re.match(r'^[a-f0-9]{32}$', input_str))
    
    return True

def get_client_ip():
    """Dapatkan IP address client dengan aman"""
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

def gen_token(no_rek: str):
    """Generate authentication token"""
    raw = f"{no_rek}:{uuid.uuid4().hex}:{time.time()}"
    return hashlib.md5(raw.encode()).hexdigest()

# ==================== JSON DATABASE MANAGER ====================
class JSONDatabase:
    def __init__(self, db_file):
        self.db_file = db_file
        self.lock = threading.Lock()
        self.init_db()
    
    def init_db(self):
        """Initialize database dengan struktur default jika tidak ada"""
        with self.lock:
            if not os.path.exists(self.db_file):
                default_data = {
                    "users": [],
                    "transactions": [],
                    "tokens": [],
                    "idempotency": [],
                    "virtual_accounts": [],
                    "loans": [],
                    "investments": [],
                    "budgets": [],
                    "next_ids": {
                        "users": 1,
                        "transactions": 1,
                        "tokens": 1,
                        "idempotency": 1,
                        "virtual_accounts": 1,
                        "loans": 1,
                        "investments": 1,
                        "budgets": 1
                    }
                }
                self._save_data(default_data)
                log("INFO", f"Database initialized: {self.db_file}", "system")
    
    def _load_data(self):
        """Load data dari file JSON"""
        try:
            with open(self.db_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Jika file corrupt, buat baru
            self.init_db()
            return self._load_data()
    
    def _save_data(self, data):
        """Save data ke file JSON"""
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            log("ERROR", f"Failed to save database: {e}", "system")
            return False
    
    def _get_next_id(self, data, table_name):
        """Generate next ID untuk table"""
        next_id = data["next_ids"][table_name]
        data["next_ids"][table_name] += 1
        return next_id
    
    # User operations
    def get_user_by_rek(self, no_rekening):
        """Get user by account number"""
        with self.lock:
            data = self._load_data()
            for user in data["users"]:
                if user["no_rekening"] == no_rekening:
                    return user
            return None
    
    def create_user(self, nama, no_rekening, pin_hash, saldo):
        """Create new user"""
        with self.lock:
            data = self._load_data()
            user = {
                "id": self._get_next_id(data, "users"),
                "nama": nama,
                "no_rekening": no_rekening,
                "pin_hash": pin_hash,
                "saldo": saldo,
                "status": "active",
                "failed_pin_attempts": 0,
                "locked_until": 0,
                "created_at": datetime.datetime.now().isoformat()
            }
            data["users"].append(user)
            success = self._save_data(data)
            return success, user
    
    def update_user(self, no_rekening, updates):
        """Update user data"""
        with self.lock:
            data = self._load_data()
            for user in data["users"]:
                if user["no_rekening"] == no_rekening:
                    user.update(updates)
                    success = self._save_data(data)
                    return success, user
            return False, None
    
    # Token operations
    def create_token(self, no_rekening, token, expires_at):
        """Create new token"""
        with self.lock:
            data = self._load_data()
            # Delete old tokens for this user
            data["tokens"] = [t for t in data["tokens"] if t["no_rekening"] != no_rekening]
            
            token_data = {
                "id": self._get_next_id(data, "tokens"),
                "no_rekening": no_rekening,
                "token": token,
                "expires_at": expires_at
            }
            data["tokens"].append(token_data)
            success = self._save_data(data)
            return success
    
    def get_token(self, token):
        """Get token data"""
        with self.lock:
            data = self._load_data()
            for token_data in data["tokens"]:
                if token_data["token"] == token:
                    return token_data
            return None
    
    def delete_token(self, token):
        """Delete token"""
        with self.lock:
            data = self._load_data()
            data["tokens"] = [t for t in data["tokens"] if t["token"] != token]
            return self._save_data(data)
    
    # Transaction operations
    def create_transaction(self, no_rekening, jenis, jumlah, keterangan=""):
        """Create new transaction"""
        with self.lock:
            data = self._load_data()
            transaction = {
                "id": self._get_next_id(data, "transactions"),
                "no_rekening": no_rekening,
                "jenis": jenis,
                "jumlah": jumlah,
                "tanggal": datetime.datetime.now().isoformat(sep=' ', timespec='seconds'),
                "keterangan": keterangan
            }
            data["transactions"].append(transaction)
            success = self._save_data(data)
            return success
    
    def get_transactions(self, no_rekening, limit=10, jenis=None, since=None, until=None):
        """Get transactions with filters"""
        with self.lock:
            data = self._load_data()
            transactions = [t for t in data["transactions"] if t["no_rekening"] == no_rekening]
            
            # Apply filters
            if jenis:
                transactions = [t for t in transactions if t["jenis"] == jenis]
            if since:
                transactions = [t for t in transactions if t["tanggal"] >= since]
            if until:
                transactions = [t for t in transactions if t["tanggal"] <= until]
            
            # Sort by date descending and limit
            transactions.sort(key=lambda x: x["tanggal"], reverse=True)
            return transactions[:limit]
    
    # Idempotency operations
    def get_idempotency(self, key, no_rekening):
        """Get idempotency response"""
        with self.lock:
            data = self._load_data()
            for item in data["idempotency"]:
                if item["idempotency_key"] == key and item["no_rekening"] == no_rekening:
                    return item
            return None
    
    def create_idempotency(self, key, no_rekening, response):
        """Create idempotency record"""
        with self.lock:
            data = self._load_data()
            # Remove old records (older than 24 hours)
            now = time.time()
            data["idempotency"] = [item for item in data["idempotency"] if now - item["created_at"] < 86400]
            
            idempotency_data = {
                "id": self._get_next_id(data, "idempotency"),
                "idempotency_key": key,
                "no_rekening": no_rekening,
                "response": response,
                "created_at": now
            }
            data["idempotency"].append(idempotency_data)
            return self._save_data(data)
    
    # Virtual Account operations
    def create_virtual_account(self, no_rekening, virtual_account, purpose, amount):
        """Create virtual account"""
        with self.lock:
            data = self._load_data()
            va_data = {
                "id": self._get_next_id(data, "virtual_accounts"),
                "no_rekening": no_rekening,
                "virtual_account": virtual_account,
                "purpose": purpose,
                "amount": amount,
                "status": "active",
                "expires_at": int(time.time()) + (24 * 60 * 60),
                "created_at": datetime.datetime.now().isoformat()
            }
            data["virtual_accounts"].append(va_data)
            success = self._save_data(data)
            return success
    
    def get_virtual_account(self, virtual_account):
        """Get virtual account data"""
        with self.lock:
            data = self._load_data()
            for va in data["virtual_accounts"]:
                if va["virtual_account"] == virtual_account:
                    return va
            return None
    
    def update_virtual_account(self, virtual_account, updates):
        """Update virtual account"""
        with self.lock:
            data = self._load_data()
            for va in data["virtual_accounts"]:
                if va["virtual_account"] == virtual_account:
                    va.update(updates)
                    return self._save_data(data)
            return False
    
    # Loan operations
    def create_loan(self, no_rekening, amount, duration_days, interest_rate=0.1):
        """Create loan application"""
        with self.lock:
            data = self._load_data()
            loan_id = self._get_next_id(data, "loans")
            loan = {
                "id": loan_id,
                "no_rekening": no_rekening,
                "amount": amount,
                "remaining_amount": amount * (1 + interest_rate),
                "interest_rate": interest_rate,
                "duration_days": duration_days,
                "status": "pending",
                "created_at": datetime.datetime.now().isoformat(),
                "due_date": (datetime.datetime.now() + datetime.timedelta(days=duration_days)).isoformat()
            }
            data["loans"].append(loan)
            return self._save_data(data), loan
    
    def get_user_loans(self, no_rekening):
        """Get all loans for a user"""
        with self.lock:
            data = self._load_data()
            return [loan for loan in data.get("loans", []) if loan["no_rekening"] == no_rekening]
    
    def update_loan(self, loan_id, updates):
        """Update loan status"""
        with self.lock:
            data = self._load_data()
            for loan in data.get("loans", []):
                if loan["id"] == loan_id:
                    loan.update(updates)
                    return self._save_data(data)
            return False
    
    # Investment operations
    def create_investment(self, no_rekening, product_id, amount):
        """Create investment"""
        with self.lock:
            data = self._load_data()
            investment = {
                "id": self._get_next_id(data, "investments"),
                "no_rekening": no_rekening,
                "product_id": product_id,
                "amount": amount,
                "current_value": amount,
                "status": "active",
                "purchase_date": datetime.datetime.now().isoformat(),
                "last_update": datetime.datetime.now().isoformat()
            }
            if "investments" not in data:
                data["investments"] = []
            data["investments"].append(investment)
            return self._save_data(data), investment
    
    def get_user_investments(self, no_rekening):
        """Get all investments for a user"""
        with self.lock:
            data = self._load_data()
            return [inv for inv in data.get("investments", []) if inv["no_rekening"] == no_rekening]
    
    def update_investment(self, investment_id, updates):
        """Update investment"""
        with self.lock:
            data = self._load_data()
            for investment in data.get("investments", []):
                if investment["id"] == investment_id:
                    investment.update(updates)
                    return self._save_data(data)
            return False
    
    # Budget operations
    def create_budget(self, no_rekening, category, monthly_limit, description=""):
        """Create monthly budget"""
        with self.lock:
            data = self._load_data()
            budget = {
                "id": self._get_next_id(data, "budgets"),
                "no_rekening": no_rekening,
                "category": category,
                "monthly_limit": monthly_limit,
                "current_spending": 0,
                "month_year": datetime.datetime.now().strftime("%Y-%m"),
                "description": description,
                "created_at": datetime.datetime.now().isoformat()
            }
            if "budgets" not in data:
                data["budgets"] = []
            data["budgets"].append(budget)
            return self._save_data(data), budget
    
    def get_user_budgets(self, no_rekening):
        """Get all budgets for a user"""
        with self.lock:
            data = self._load_data()
            return [budget for budget in data.get("budgets", []) if budget["no_rekening"] == no_rekening]
    
    def update_budget(self, budget_id, updates):
        """Update budget"""
        with self.lock:
            data = self._load_data()
            for budget in data.get("budgets", []):
                if budget["id"] == budget_id:
                    budget.update(updates)
                    return self._save_data(data)
            return False
    
    # Admin operations
    def get_all_users(self):
        """Get all users for admin"""
        with self.lock:
            data = self._load_data()
            return data["users"]
    
    def get_stats(self):
        """Get system statistics"""
        with self.lock:
            data = self._load_data()
            total_users = len(data["users"])
            active_users = len([u for u in data["users"] if u.get("status", "active") == "active"])
            total_balance = sum(u["saldo"] for u in data["users"])
            total_transactions = len(data["transactions"])
            
            # Daily activity
            today = datetime.datetime.now().date().isoformat()
            daily_tx = [t for t in data["transactions"] if t["tanggal"].startswith(today)]
            daily_activity = {}
            for tx in daily_tx:
                jenis = tx["jenis"]
                if jenis not in daily_activity:
                    daily_activity[jenis] = {"count": 0, "total": 0}
                daily_activity[jenis]["count"] += 1
                daily_activity[jenis]["total"] += tx["jumlah"]
            
            return {
                "total_users": total_users,
                "active_users": active_users,
                "total_balance": total_balance,
                "total_transactions": total_transactions,
                "daily_activity": daily_activity
            }

# Initialize database
db = JSONDatabase(DB_FILE)

# ==================== DB-DEPENDENT UTILITIES ====================
def gen_no_rekening():
    """Generate 10-digit numeric account number yang unik"""
    while True:
        no_rek = str(uuid.uuid4().int)[:10].zfill(10)
        # Pastikan nomor rekening unik
        if not db.get_user_by_rek(no_rek):
            return no_rek

def create_virtual_account(no_rek: str, purpose: str = "general", amount: float = 0) -> str:
    """Buat virtual account untuk transaksi spesifik"""
    va_prefix = "88"
    va_middle = str(uuid.uuid4().int)[:12]
    va_suffix = str(int(time.time()))[-2:]
    
    virtual_account = f"{va_prefix}{va_middle}{va_suffix}"
    
    success = db.create_virtual_account(no_rek, virtual_account, purpose, amount)
    if success:
        audit_log("VIRTUAL_ACCOUNT_CREATED", no_rek, f"VA: {virtual_account} for {purpose}")
        return virtual_account
    else:
        raise Exception("Failed to create virtual account")

# ==================== AUTHENTICATION MIDDLEWARE ====================
def enhanced_token_required(f):
    """Enhanced token validation dengan audit"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        client_ip = get_client_ip()
            
        if 'Authorization' in request.headers:
            auth = request.headers.get('Authorization', '')
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1].strip()
        
        if not token:
            audit_log("UNAUTHORIZED_ACCESS", "unknown", "Missing token", client_ip)
            return jsonify({"error": "Token diperlukan"}), 401
        
        if not validate_input(token, 'token'):
            audit_log("INVALID_TOKEN_FORMAT", "unknown", "Invalid token format", client_ip)
            return jsonify({"error": "Format token tidak valid"}), 401
        
        token_data = db.get_token(token)
        if not token_data:
            audit_log("INVALID_TOKEN", "unknown", f"Token: {token[:8]}...", client_ip)
            return jsonify({"error": "Token tidak valid"}), 401
            
        if int(token_data['expires_at']) < int(time.time()):
            db.delete_token(token)
            audit_log("EXPIRED_TOKEN", token_data['no_rekening'], "Token expired", client_ip)
            return jsonify({"error": "Token kedaluwarsa"}), 401
        
        # Attach account dan audit
        request.no_rekening = token_data['no_rekening']
        request.client_ip = client_ip
        
        return f(*args, **kwargs)
    return decorated

# ==================== API ENDPOINTS ====================
@app.route("/")
def index():
    """Root endpoint"""
    return jsonify({
        "service": APP_NAME, 
        "status": "running", 
        "time": datetime.datetime.now().isoformat(),
        "version": "4.0",
        "database": "JSON"
    })

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        # Test database access
        stats = db.get_stats()
        db_status = "healthy"
    except Exception as e:
        db_status = "unhealthy"
        log("ERROR", f"Database health check failed: {e}", "system")
    
    return jsonify({
        "status": "running",
        "service": APP_NAME,
        "database": db_status,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route("/register", methods=["POST"])
def register():
    """Register new account"""
    client_ip = get_client_ip()
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        nama = data.get("nama", "").strip()
        pin = data.get("pin", "")
        saldo = float(data.get("saldo", 0))
        
        if not nama or not pin:
            return jsonify({"error": "nama dan pin wajib"}), 400
        
        if not validate_input(nama, 'name', 50):
            return jsonify({"error": "Format nama tidak valid. Hanya huruf, spasi, dan karakter -.' yang diperbolehkan"}), 400
            
        if not validate_input(pin, 'pin'):
            return jsonify({"error": "PIN harus 4-8 digit angka"}), 400
            
        if saldo < 0 or saldo > 100000000:
            return jsonify({"error": "Saldo tidak valid. Maksimal 100.000.000"}), 400
        
        no_rek = gen_no_rekening()
        pin_h = hash_pin(pin)
        
        success, user = db.create_user(nama, no_rek, pin_h, saldo)
        if not success:
            return jsonify({"error": "Gagal menyimpan data user"}), 500
        
        audit_log("REGISTER_SUCCESS", no_rek, f"nama={nama} saldo={saldo}", client_ip)
        return jsonify({"pesan": "registrasi berhasil", "no_rekening": no_rek})
        
    except Exception as e:
        log("ERROR", f"Register error: {str(e)}", "system", client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/login", methods=["POST"])
def login():
    """Login endpoint"""
    client_ip = get_client_ip()
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        no_rek = data.get("no_rekening", "").strip()
        pin = data.get("pin", "")
        
        if not no_rek or not pin:
            return jsonify({"error": "no_rekening dan pin dibutuhkan"}), 400
        
        if not validate_input(no_rek, 'rekening'):
            return jsonify({"error": "Format nomor rekening tidak valid"}), 400
        
        user = db.get_user_by_rek(no_rek)
        if not user:
            audit_log("LOGIN_FAILED", "unknown", f"Rekening tidak ditemukan: {no_rek}", client_ip)
            return jsonify({"error": "rekening tidak ditemukan"}), 404
        
        # Check account lock
        now_ts = int(time.time())
        if user.get('status') == 'locked' and user.get('locked_until', 0) and int(user.get('locked_until', 0)) > now_ts:
            remaining_time = int(user.get('locked_until', 0)) - now_ts
            audit_log("LOGIN_BLOCKED", no_rek, f"Akun terkunci, sisa: {remaining_time}s", client_ip)
            return jsonify({"error": f"Akun terkunci, coba lagi dalam {remaining_time} detik"}), 403
        
        # Verify PIN
        if not verify_pin(pin, user.get('pin_hash', '')):
            failed = user.get('failed_pin_attempts', 0) + 1
            locked_until = user.get('locked_until', 0)
            status = user.get('status', 'active')
            
            if failed >= FAILED_PIN_LIMIT:
                locked_until = now_ts + ACCOUNT_LOCK_SECONDS
                status = 'locked'
                audit_log("ACCOUNT_LOCKED", no_rek, f"reason=failed_pin_limit attempts={failed}", client_ip)
            
            db.update_user(no_rek, {
                "failed_pin_attempts": failed,
                "status": status,
                "locked_until": locked_until
            })
            
            remaining_attempts = FAILED_PIN_LIMIT - failed
            audit_log("LOGIN_FAILED", no_rek, f"Salah PIN, sisa percobaan: {remaining_attempts}", client_ip)
            return jsonify({"error": f"PIN salah. Sisa percobaan: {remaining_attempts}"}), 403
        
        # Login successful
        db.update_user(no_rek, {
            "failed_pin_attempts": 0,
            "status": "active",
            "locked_until": 0
        })
        
        # Generate token
        token = gen_token(no_rek)
        expires = now_ts + TOKEN_TTL_SECONDS
        
        # Save token
        db.create_token(no_rek, token, expires)
        
        audit_log("LOGIN_SUCCESS", no_rek, "Login berhasil", client_ip)
        return jsonify({
            "pesan": "login sukses", 
            "token": token, 
            "expires_in": TOKEN_TTL_SECONDS,
            "user": user.get('nama', '')
        })
        
    except Exception as e:
        log("ERROR", f"Login error: {str(e)}", "system", client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/logout", methods=["POST"])
@enhanced_token_required
def logout():
    """Logout endpoint"""
    token = None
    auth = request.headers.get('Authorization', '')
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
    
    db.delete_token(token)
    audit_log("LOGOUT", request.no_rekening, "User logged out", request.client_ip)
    return jsonify({"pesan": "logout sukses"})

@app.route("/saldo", methods=["GET"])
@enhanced_token_required
def saldo():
    """Check balance"""
    no_rek = request.no_rekening
    
    user = db.get_user_by_rek(no_rek)
    if not user:
        return jsonify({"error": "rekening tidak ditemukan"}), 404
    
    return jsonify({"no_rekening": no_rek, "saldo": user.get('saldo', 0)})

@app.route("/ubah_pin", methods=["POST"])
@enhanced_token_required
def ubah_pin():
    """Change PIN"""
    no_rek = request.no_rekening
    client_ip = request.client_ip
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        old_pin = data.get("old_pin")
        new_pin = data.get("new_pin")
        
        if not old_pin or not new_pin:
            return jsonify({"error": "old_pin dan new_pin diperlukan"}), 400
        
        user = db.get_user_by_rek(no_rek)
        if not user or not verify_pin(old_pin, user.get('pin_hash', '')):
            audit_log("CHANGE_PIN_FAILED", no_rek, "PIN lama salah", client_ip)
            return jsonify({"error": "PIN lama salah"}), 403
        
        if not validate_input(new_pin, 'pin'):
            return jsonify({"error": "PIN baru harus 4-8 digit angka"}), 400
        
        db.update_user(no_rek, {"pin_hash": hash_pin(new_pin)})
        audit_log("PIN_CHANGED", no_rek, "PIN berhasil diubah", client_ip)
        return jsonify({"pesan": "PIN berhasil diubah"})
        
    except Exception as e:
        log("ERROR", f"Change PIN error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

# ==================== TRANSACTION ENDPOINTS ====================
@app.route("/setor", methods=["POST"])
@enhanced_token_required
def setor():
    """Deposit money"""
    no_rek = request.no_rekening
    client_ip = request.client_ip

    # Idempotency check
    key = request.headers.get("Idempotency-Key")
    if key:
        idem_data = db.get_idempotency(key, no_rek)
        if idem_data:
            try:
                return jsonify(json.loads(idem_data["response"]))
            except:
                pass

    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        jumlah = float(data.get("jumlah", 0))
        
        if jumlah <= 0:
            return jsonify({"error": "Jumlah harus lebih dari 0"}), 400
        
        if jumlah > 100000000:
            return jsonify({"error": "Jumlah deposit terlalu besar"}), 400

        user = db.get_user_by_rek(no_rek)
        if not user:
            return jsonify({"error": "rekening tidak ditemukan"}), 404
            
        saldo_baru = user.get('saldo', 0) + jumlah
        db.update_user(no_rek, {"saldo": saldo_baru})
        db.create_transaction(no_rek, "DEPOSIT", jumlah, "Setor tunai")
        
        resp = {"pesan": "Setor berhasil", "saldo": saldo_baru}
        
        # Store idempotency
        if key:
            db.create_idempotency(key, no_rek, json.dumps(resp))
            
        audit_log("DEPOSIT", no_rek, f"Jumlah: {jumlah}", client_ip)
        return jsonify(resp)
        
    except Exception as e:
        log("ERROR", f"Deposit error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/tarik", methods=["POST"])
@enhanced_token_required
def tarik():
    """Withdraw money"""
    no_rek = request.no_rekening
    client_ip = request.client_ip

    # Idempotency check
    key = request.headers.get("Idempotency-Key")
    if key:
        idem_data = db.get_idempotency(key, no_rek)
        if idem_data:
            try:
                return jsonify(json.loads(idem_data["response"]))
            except:
                pass

    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        jumlah = float(data.get("jumlah", 0))
        
        if jumlah <= 0:
            return jsonify({"error": "Jumlah harus lebih dari 0"}), 400
            
        if jumlah % WITHDRAWAL_MULTIPLE != 0 or jumlah < MIN_WITHDRAWAL:
            return jsonify({"error": f"Tarik harus kelipatan {WITHDRAWAL_MULTIPLE} dan minimal {MIN_WITHDRAWAL}"}), 400

        user = db.get_user_by_rek(no_rek)
        if not user:
            return jsonify({"error": "rekening tidak ditemukan"}), 404
            
        if user.get('saldo', 0) < jumlah:
            return jsonify({"error": "Saldo tidak cukup"}), 400
            
        saldo_baru = user.get('saldo', 0) - jumlah
        db.update_user(no_rek, {"saldo": saldo_baru})
        db.create_transaction(no_rek, "WITHDRAW", -jumlah, "Tarik tunai")
        
        resp = {"pesan": "Tarik berhasil", "saldo": saldo_baru}
        
        if key:
            db.create_idempotency(key, no_rek, json.dumps(resp))
            
        audit_log("WITHDRAW", no_rek, f"Jumlah: {jumlah}", client_ip)
        return jsonify(resp)
        
    except Exception as e:
        log("ERROR", f"Withdraw error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/transfer", methods=["POST"])
@enhanced_token_required
def transfer():
    """Transfer money"""
    no_rek = request.no_rekening
    client_ip = request.client_ip

    # Idempotency check
    key = request.headers.get("Idempotency-Key")
    if key:
        idem_data = db.get_idempotency(key, no_rek)
        if idem_data:
            try:
                return jsonify(json.loads(idem_data["response"]))
            except:
                pass

    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        tujuan = data.get("ke", "").strip()
        jumlah = float(data.get("jumlah", 0))
        
        if not tujuan or jumlah <= 0:
            return jsonify({"error": "tujuan dan jumlah diperlukan"}), 400
            
        if not validate_input(tujuan, 'rekening'):
            return jsonify({"error": "Format rekening tujuan tidak valid"}), 400
            
        if tujuan == no_rek:
            return jsonify({"error": "tidak bisa transfer ke rekening sendiri"}), 400

        # Check sender and receiver
        pengirim = db.get_user_by_rek(no_rek)
        penerima = db.get_user_by_rek(tujuan)
        
        if not pengirim:
            return jsonify({"error": "rekening pengirim tidak ditemukan"}), 404
            
        if not penerima:
            return jsonify({"error": "rekening tujuan tidak ditemukan"}), 404
            
        if pengirim.get('saldo', 0) < jumlah:
            return jsonify({"error": "Saldo tidak cukup"}), 400

        # Simulate network delay
        delay = random.uniform(TRANSFER_NETWORK_DELAY_MIN, TRANSFER_NETWORK_DELAY_MAX)
        time.sleep(delay)

        # Process transfer
        saldo_pengirim = pengirim.get('saldo', 0) - jumlah
        saldo_penerima = penerima.get('saldo', 0) + jumlah
        
        db.update_user(no_rek, {"saldo": saldo_pengirim})
        db.update_user(tujuan, {"saldo": saldo_penerima})
        
        db.create_transaction(no_rek, "TRANSFER_OUT", -jumlah, f"Transfer ke {tujuan}")
        db.create_transaction(tujuan, "TRANSFER_IN", jumlah, f"Transfer dari {no_rek}")
        
        resp = {"pesan": "Transfer berhasil", "saldo": saldo_pengirim}
        
        if key:
            db.create_idempotency(key, no_rek, json.dumps(resp))
            
        audit_log("TRANSFER", no_rek, f"Ke: {tujuan} Jumlah: {jumlah}", client_ip)
        
        return jsonify(resp)
        
    except Exception as e:
        log("ERROR", f"Transfer error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/riwayat", methods=["GET"])
@enhanced_token_required
def riwayat():
    """Transaction history"""
    no_rek = request.no_rekening
    
    try:
        limit = int(request.args.get("limit", 10))
        since = request.args.get("since")
        until = request.args.get("until")
        jenis = request.args.get("jenis")
        
        if limit > 100:
            limit = 100
            
        transactions = db.get_transactions(no_rek, limit, jenis, since, until)
        
        data = [{
            "jenis": t['jenis'], 
            "jumlah": t['jumlah'], 
            "tanggal": t['tanggal'], 
            "keterangan": t['keterangan']
        } for t in transactions]
        
        return jsonify({"no_rekening": no_rek, "riwayat": data})
        
    except Exception as e:
        log("ERROR", f"History error: {str(e)}", no_rek, request.client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

# ==================== VIRTUAL ACCOUNT ENDPOINTS ====================
@app.route("/virtual_account", methods=["POST"])
@enhanced_token_required
def create_va():
    """Create virtual account"""
    no_rek = request.no_rekening
    client_ip = request.client_ip
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        purpose = data.get("purpose", "general")
        amount = float(data.get("amount", 0))
        
        if amount < 0:
            return jsonify({"error": "Amount tidak valid"}), 400
        
        virtual_account = create_virtual_account(no_rek, purpose, amount)
        
        return jsonify({
            "pesan": "Virtual account berhasil dibuat",
            "virtual_account": virtual_account,
            "purpose": purpose,
            "amount": amount,
            "expires_in": "24 jam"
        })
        
    except Exception as e:
        log("ERROR", f"VA creation error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/virtual_account/pay", methods=["POST"])
def pay_va():
    """Pay to virtual account"""
    client_ip = get_client_ip()
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        virtual_account = data.get("virtual_account", "").strip()
        amount = float(data.get("amount", 0))
        
        if not virtual_account or amount <= 0:
            return jsonify({"error": "virtual_account dan amount diperlukan"}), 400

        va_data = db.get_virtual_account(virtual_account)
        if not va_data:
            return jsonify({"error": "Virtual account tidak valid"}), 404
        
        if int(va_data.get('expires_at', 0)) < time.time():
            db.update_virtual_account(virtual_account, {"status": "expired"})
            return jsonify({"error": "Virtual account sudah kedaluwarsa"}), 400
        
        # Process payment
        rek_tujuan = va_data['no_rekening']
        user = db.get_user_by_rek(rek_tujuan)
        
        if not user:
            return jsonify({"error": "Rekening tujuan tidak ditemukan"}), 404
        
        saldo_baru = user.get('saldo', 0) + amount
        db.update_user(rek_tujuan, {"saldo": saldo_baru})
        db.update_virtual_account(virtual_account, {"status": "paid"})
        
        db.create_transaction(rek_tujuan, "VA_PAYMENT", amount, f"Pembayaran VA: {virtual_account}")
        
        audit_log("VA_PAYMENT_SUCCESS", rek_tujuan, f"VA: {virtual_account} Amount: {amount}", client_ip)
        
        return jsonify({
            "pesan": "Pembayaran berhasil",
            "virtual_account": virtual_account,
            "amount": amount,
            "rekening_tujuan": rek_tujuan
        })
        
    except Exception as e:
        log("ERROR", f"VA payment error: {str(e)}", "system", client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

# ==================== LOAN ENDPOINTS ====================
@app.route("/pinjaman/ajukan", methods=["POST"])
@enhanced_token_required
def ajukan_pinjaman():
    """Apply for loan"""
    no_rek = request.no_rekening
    client_ip = request.client_ip
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        amount = float(data.get("jumlah", 0))
        duration_days = int(data.get("durasi_hari", 30))
        
        if amount < 100000 or amount > 10000000:
            return jsonify({"error": "Jumlah pinjaman antara 100.000 - 10.000.000"}), 400
            
        success, loan = db.create_loan(no_rek, amount, duration_days)
        if not success:
            return jsonify({"error": "Gagal mengajukan pinjaman"}), 500
            
        audit_log("LOAN_APPLIED", no_rek, f"Amount: {amount}, Duration: {duration_days} days", client_ip)
        return jsonify({
            "pesan": "Pengajuan pinjaman berhasil",
            "id_pinjaman": loan["id"],
            "jumlah": amount,
            "total_pengembalian": loan["remaining_amount"],
            "tanggal_jatuh_tempo": loan["due_date"]
        })
        
    except Exception as e:
        log("ERROR", f"Loan application error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/pinjaman/daftar", methods=["GET"])
@enhanced_token_required
def daftar_pinjaman():
    """Get user's loans"""
    no_rek = request.no_rekening
    
    try:
        loans = db.get_user_loans(no_rek)
        data = [{
            "id": loan["id"],
            "jumlah": loan["amount"],
            "sisa_tagihan": loan["remaining_amount"],
            "status": loan["status"],
            "tanggal_pengajuan": loan["created_at"],
            "tanggal_jatuh_tempo": loan["due_date"]
        } for loan in loans]
        
        return jsonify({"pinjaman": data})
        
    except Exception as e:
        log("ERROR", f"Get loans error: {str(e)}", no_rek, request.client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

# ==================== INVESTMENT ENDPOINTS ====================
@app.route("/investasi/produk", methods=["GET"])
@enhanced_token_required
def daftar_produk_investasi():
    """Get investment products"""
    return jsonify({"produk": INVESTMENT_PRODUCTS})

@app.route("/investasi/beli", methods=["POST"])
@enhanced_token_required
def beli_investasi():
    """Buy investment product"""
    no_rek = request.no_rekening
    client_ip = request.client_ip
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        product_id = data.get("produk_id")
        amount = float(data.get("jumlah", 0))
        
        if product_id not in INVESTMENT_PRODUCTS:
            return jsonify({"error": "Produk investasi tidak ditemukan"}), 404
            
        product = INVESTMENT_PRODUCTS[product_id]
        
        if amount < product["min_amount"]:
            return jsonify({"error": f"Minimum investasi {product['min_amount']}"}), 400
            
        user = db.get_user_by_rek(no_rek)
        if user.get('saldo', 0) < amount:
            return jsonify({"error": "Saldo tidak cukup"}), 400
            
        # Deduct balance
        saldo_baru = user.get('saldo', 0) - amount
        db.update_user(no_rek, {"saldo": saldo_baru})
        
        # Create investment
        success, investment = db.create_investment(no_rek, product_id, amount)
        if not success:
            # Rollback balance if investment creation fails
            db.update_user(no_rek, {"saldo": user.get('saldo', 0)})
            return jsonify({"error": "Gagal membuat investasi"}), 500
            
        db.create_transaction(no_rek, "INVESTMENT", -amount, f"Beli {product['name']}")
        
        audit_log("INVESTMENT_PURCHASED", no_rek, f"Product: {product_id}, Amount: {amount}", client_ip)
        return jsonify({
            "pesan": "Pembelian investasi berhasil",
            "produk": product["name"],
            "jumlah": amount,
            "saldo_tersisa": saldo_baru
        })
        
    except Exception as e:
        log("ERROR", f"Investment purchase error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/investasi/daftar", methods=["GET"])
@enhanced_token_required
def daftar_investasi():
    """Get user's investments"""
    no_rek = request.no_rekening
    
    try:
        investments = db.get_user_investments(no_rek)
        data = []
        for inv in investments:
            product_id = inv["product_id"]
            product = INVESTMENT_PRODUCTS.get(product_id, {"name": "Unknown", "return_rate": 0})
            data.append({
                "id": inv["id"],
                "produk": product["name"],
                "jumlah_investasi": inv["amount"],
                "nilai_sekarang": inv["current_value"],
                "tanggal_pembelian": inv["purchase_date"],
                "status": inv["status"]
            })
        
        return jsonify({"investasi": data})
        
    except Exception as e:
        log("ERROR", f"Get investments error: {str(e)}", no_rek, request.client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

# ==================== BUDGETING ENDPOINTS ====================
@app.route("/anggaran/buat", methods=["POST"])
@enhanced_token_required
def buat_anggaran():
    """Create budget"""
    no_rek = request.no_rekening
    client_ip = request.client_ip
    
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "Data JSON diperlukan"}), 400
            
        category = data.get("kategori")
        monthly_limit = float(data.get("batas_bulanan", 0))
        description = data.get("deskripsi", "")
        
        if not category or monthly_limit <= 0:
            return jsonify({"error": "Kategori dan batas bulanan diperlukan"}), 400
            
        success, budget = db.create_budget(no_rek, category, monthly_limit, description)
        if not success:
            return jsonify({"error": "Gagal membuat anggaran"}), 500
            
        audit_log("BUDGET_CREATED", no_rek, f"Category: {category}, Limit: {monthly_limit}", client_ip)
        return jsonify({
            "pesan": "Anggaran berhasil dibuat",
            "id_anggaran": budget["id"],
            "kategori": category,
            "batas_bulanan": monthly_limit
        })
        
    except Exception as e:
        log("ERROR", f"Budget creation error: {str(e)}", no_rek, client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/anggaran/daftar", methods=["GET"])
@enhanced_token_required
def daftar_anggaran():
    """Get user's budgets"""
    no_rek = request.no_rekening
    
    try:
        budgets = db.get_user_budgets(no_rek)
        data = [{
            "id": budget["id"],
            "kategori": budget["category"],
            "batas_bulanan": budget["monthly_limit"],
            "pengeluaran_sekarang": budget["current_spending"],
            "sisa_anggaran": budget["monthly_limit"] - budget["current_spending"],
            "bulan_tahun": budget["month_year"],
            "deskripsi": budget["description"]
        } for budget in budgets]
        
        return jsonify({"anggaran": data})
        
    except Exception as e:
        log("ERROR", f"Get budgets error: {str(e)}", no_rek, request.client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

# ==================== FINANCIAL DASHBOARD ====================
@app.route("/dashboard", methods=["GET"])
@enhanced_token_required
def financial_dashboard():
    """Financial dashboard with summary"""
    no_rek = request.no_rekening
    
    try:
        user = db.get_user_by_rek(no_rek)
        transactions = db.get_transactions(no_rek, limit=5)
        
        # Calculate monthly spending
        today = datetime.datetime.now()
        first_day_of_month = today.replace(day=1).isoformat()[:10]
        monthly_tx = db.get_transactions(no_rek, limit=100, since=first_day_of_month)
        
        monthly_spending = sum(tx["jumlah"] for tx in monthly_tx if tx["jumlah"] < 0)
        monthly_income = sum(tx["jumlah"] for tx in monthly_tx if tx["jumlah"] > 0)
        
        # Get investments
        investments = db.get_user_investments(no_rek)
        
        # Get loans
        loans = db.get_user_loans(no_rek)
        
        # Get budgets
        budgets = db.get_user_budgets(no_rek)
        
        return jsonify({
            "ringkasan_keuangan": {
                "saldo": user.get('saldo', 0),
                "pemasukan_bulan_ini": monthly_income,
                "pengeluaran_bulan_ini": abs(monthly_spending),
                "total_investasi": sum(inv["amount"] for inv in investments),
                "total_pinjaman": sum(loan["remaining_amount"] for loan in loans if loan["status"] == "approved")
            },
            "transaksi_terakhir": [{
                "jenis": t['jenis'], 
                "jumlah": t['jumlah'], 
                "tanggal": t['tanggal'], 
                "keterangan": t['keterangan']
            } for t in transactions],
            "jumlah_transaksi_bulan_ini": len(monthly_tx),
            "jumlah_anggaran_aktif": len(budgets)
        })
        
    except Exception as e:
        log("ERROR", f"Dashboard error: {str(e)}", no_rek, request.client_ip)
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

# ==================== ADMIN ENDPOINTS ====================
@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    """Admin dashboard"""
    token = request.args.get("admin_token")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "admin token invalid"}), 403
    
    try:
        stats = db.get_stats()
        
        daily_activity = []
        for jenis, data in stats["daily_activity"].items():
            daily_activity.append({
                "jenis": jenis,
                "count": data["count"],
                "total_amount": data["total"]
            })
        
        return jsonify({
            "total_users": stats["total_users"],
            "active_users": stats["active_users"],
            "locked_users": stats["total_users"] - stats["active_users"],
            "total_balance": stats["total_balance"],
            "total_transactions": stats["total_transactions"],
            "daily_activity": daily_activity
        })
        
    except Exception as e:
        log("ERROR", f"Admin dashboard error: {str(e)}", "admin", get_client_ip())
        return jsonify({"error": "Terjadi kesalahan sistem"}), 500

@app.route("/admin/accounts", methods=["GET"])
def admin_accounts():
    """Get all accounts"""
    token = request.args.get("admin_token")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "admin token invalid"}), 403
    
    users = db.get_all_users()
    
    data = [{
        "no_rekening": u['no_rekening'], 
        "nama": u['nama'], 
        "saldo": u['saldo'], 
        "status": u.get('status', 'active'), 
        "created_at": u['created_at']
    } for u in users]
    
    return jsonify({"accounts": data})

# ==================== SECURITY HEADERS ====================
@app.after_request
def set_security_headers(response):
    """Set security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint tidak ditemukan"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method tidak diizinkan"}), 405

@app.errorhandler(500)
def internal_error(error):
    log("ERROR", f"Internal server error: {str(error)}", "system", get_client_ip())
    return jsonify({"error": "Terjadi kesalahan internal server"}), 500

# ==================== STARTUP ====================
def check_environment():
    """Check environment variables"""
    warnings = []
    
    if ADMIN_TOKEN == "admintoken123":
        warnings.append("ADMIN_TOKEN masih menggunakan default value")
    
    if os.environ.get("FLASK_SECRET_KEY") is None:
        warnings.append("FLASK_SECRET_KEY tidak di-set, menggunakan random")
    
    for warning in warnings:
        log("WARNING", warning, "system")

if __name__ == "__main__":
    check_environment()
    
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a").close()
    
    log("INFO", f"Starting {APP_NAME} with JSON Database", "system")
    app.run(host="0.0.0.0", port=5000, debug=False)