import asyncio
import json
import logging
import threading
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Union
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import blackboxprotobuf
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ---------- Configuration ----------
class Config:
    BMW_API_URL = "http://187.127.175.208:5001/Bmw"
    FOLLOW_ENDPOINT = "https://client.ind.freefiremobile.com/Follow"
    
    AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    
    HEADERS_TEMPLATE = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1"
    }
    
    TOKEN_REFRESH_INTERVAL = 4 * 3600
    MAX_WORKERS = 20
    JWT_RETRIES = 3
    FOLLOW_RETRIES = 2
    ACCOUNTS_FILE = "accounts.txt"
    TOKENS_FILE = "tokens.json"

# ---------- ProtoWriter (Manual Implementation) ----------
class ProtoWriter:
    @staticmethod
    def varint(value):
        result = []
        while value > 127:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)

    @staticmethod
    def tag(field_num, wire_type):
        return ProtoWriter.varint((field_num << 3) | wire_type)

    @staticmethod
    def write_varint(field_num, value):
        return ProtoWriter.tag(field_num, 0) + ProtoWriter.varint(value)

    @staticmethod
    def write_string(field_num, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        return ProtoWriter.tag(field_num, 2) + ProtoWriter.varint(len(value)) + value

    @staticmethod
    def create_message(fields):
        result = bytearray()
        for field_num, value in sorted(fields.items()):
            if isinstance(value, int):
                result.extend(ProtoWriter.write_varint(field_num, value))
            elif isinstance(value, str):
                result.extend(ProtoWriter.write_string(field_num, value))
            elif isinstance(value, bytes):
                result.extend(ProtoWriter.write_string(field_num, value))
            else:
                raise ValueError(f"Unsupported field type for {field_num}")
        return bytes(result)

# ---------- AES Encryption ----------
def encrypt(data: bytes) -> bytes:
    cipher = AES.new(Config.AES_KEY, AES.MODE_CBC, Config.AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def build_follow_payload(target_uid: int) -> bytes:
    fields = {1: target_uid}
    return ProtoWriter.create_message(fields)

def decode_response(data: bytes) -> Dict:
    """Decode protobuf response using blackboxprotobuf."""
    try:
        # Use protobuf_to_json instead of protobuf_to_dict
        decoded = blackboxprotobuf.protobuf_to_json(data)
        return json.loads(decoded)
    except Exception as e:
        # Fallback: return hex representation
        return {
            "error": f"Could not decode protobuf: {str(e)}",
            "hex_preview": data[:100].hex()
        }

# ---------- Enhanced Account Loading ----------
def load_accounts(file_path: str) -> List[Tuple[str, str]]:
    """Load accounts from file with support for multiple formats."""
    accounts = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                uid = None
                password = None
                
                # Format 1: "UiD => 123 | PaSsWoRd => ABC"
                if '=>' in line and '|' in line:
                    try:
                        parts = line.split('|')
                        if len(parts) >= 2:
                            uid_part = parts[0].strip()
                            pwd_part = parts[1].strip()
                            
                            if '=>' in uid_part:
                                uid = uid_part.split('=>')[1].strip()
                            if '=>' in pwd_part:
                                password = pwd_part.split('=>')[1].strip()
                    except:
                        pass
                
                # Format 2: "uid:password" or "uid:password:extra"
                elif ':' in line and not line.startswith('{'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        # Check if first part is numeric (UID)
                        if parts[0].strip().isdigit():
                            uid = parts[0].strip()
                            password = parts[1].strip()
                
                # Format 3: JSON-like format
                elif line.startswith('{'):
                    try:
                        # Try to parse as JSON
                        data = json.loads(line.replace("'", '"'))
                        uid = str(data.get('uid', ''))
                        password = str(data.get('password', ''))
                    except:
                        # Try regex extraction
                        uid_match = re.search(r'["\']?uid["\']?\s*:\s*(\d+)', line)
                        pwd_match = re.search(r'["\']?password["\']?\s*:\s*["\']([^"\']+)["\']', line)
                        if uid_match and pwd_match:
                            uid = uid_match.group(1)
                            password = pwd_match.group(1)
                
                # Format 4: Plain UID and password separated by space
                else:
                    # Try to find UID (numbers) and password (any string)
                    uid_match = re.search(r'\b(\d+)\b', line)
                    if uid_match:
                        uid = uid_match.group(1)
                        # Remove the UID from the line to get password
                        remaining = re.sub(r'\b\d+\b', '', line, count=1).strip()
                        if remaining:
                            password = remaining
                
                # Validate and add account
                if uid and password:
                    accounts.append((str(uid).strip(), str(password).strip()))
                    logger.debug(f"Loaded account: {uid}")
                else:
                    logger.warning(f"Could not parse line {line_num}: {line}")
    
    except FileNotFoundError:
        logger.warning(f"Accounts file not found: {file_path}")
    except Exception as e:
        logger.error(f"Error loading accounts: {e}")
    
    return accounts

# ---------- Token Manager ----------
class TokenManager:
    def __init__(self):
        self.tokens: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        self._load_tokens()
        self._start_token_refresh_scheduler()
    
    def _load_tokens(self):
        try:
            with open(Config.TOKENS_FILE, 'r') as f:
                self.tokens = json.load(f)
                logger.info(f"Loaded {len(self.tokens)} tokens from file")
        except FileNotFoundError:
            logger.info("No existing tokens file found, starting fresh")
            self.tokens = {}
        except Exception as e:
            logger.error(f"Error loading tokens: {e}")
            self.tokens = {}
    
    def _save_tokens(self):
        try:
            with open(Config.TOKENS_FILE, 'w') as f:
                json.dump(self.tokens, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving tokens: {e}")
    
    def _fetch_jwt_for_account(self, uid: str, password: str) -> Optional[str]:
        try:
            response = requests.get(
                Config.BMW_API_URL,
                params={"uid": uid, "password": password},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                jwt_token = data.get("JwT_ToKeN")
                if jwt_token and len(jwt_token) > 50:
                    with self._lock:
                        self.tokens[uid] = {
                            "jwt": jwt_token,
                            "data": data,
                            "last_refresh": time.time(),
                            "password": password
                        }
                    self._save_tokens()
                    return jwt_token
                else:
                    logger.warning(f"Invalid JWT format for UID: {uid}")
            else:
                logger.warning(f"Failed to fetch JWT for UID {uid}: HTTP {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error fetching JWT for UID {uid}: {e}")
        
        return None
    
    def _refresh_all_tokens(self):
        accounts = load_accounts(Config.ACCOUNTS_FILE)
        logger.info(f"Refreshing tokens for {len(accounts)} accounts")
        
        success_count = 0
        for uid, password in accounts:
            if self._fetch_jwt_for_account(uid, password):
                success_count += 1
        
        logger.info(f"Token refresh complete: {success_count}/{len(accounts)} successful")
    
    def _start_token_refresh_scheduler(self):
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            self._refresh_all_tokens,
            trigger=IntervalTrigger(seconds=Config.TOKEN_REFRESH_INTERVAL),
            id='refresh_tokens',
            replace_existing=True
        )
        scheduler.start()
        logger.info(f"Token refresh scheduler started (interval: {Config.TOKEN_REFRESH_INTERVAL}s)")
        
        # Perform initial refresh
        self._refresh_all_tokens()
    
    def get_token(self, uid: str) -> Optional[str]:
        with self._lock:
            token_data = self.tokens.get(uid)
            if token_data:
                return token_data.get("jwt")
        return None
    
    def get_all_tokens(self) -> List[str]:
        with self._lock:
            return [
                data["jwt"] 
                for data in self.tokens.values() 
                if data.get("jwt")
            ]
    
    def get_token_count(self) -> int:
        return len(self.tokens)

# ---------- Follow Sender ----------
def send_follow(jwt: str, target_uid: int) -> Tuple[Optional[int], bytes, Optional[str]]:
    plain = build_follow_payload(target_uid)
    encrypted = encrypt(plain)
    
    headers = Config.HEADERS_TEMPLATE.copy()
    headers["Authorization"] = f"Bearer {jwt}"
    
    for attempt in range(Config.FOLLOW_RETRIES + 1):
        try:
            response = requests.post(
                Config.FOLLOW_ENDPOINT,
                headers=headers,
                data=encrypted,
                timeout=15,
                verify=False
            )
            return response.status_code, response.content, None
        except Exception as e:
            if attempt < Config.FOLLOW_RETRIES:
                time.sleep(1)
            else:
                return None, b'', str(e)
    
    return None, b'', "Max retries exceeded"

# ---------- FastAPI Application ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting FreeFire Follow Bot API")
    app.state.token_manager = TokenManager()
    app.state.executor = ThreadPoolExecutor(max_workers=Config.MAX_WORKERS)
    
    yield
    
    logger.info("Shutting down FreeFire Follow Bot API")
    app.state.executor.shutdown(wait=True)

app = FastAPI(
    title="FreeFire Follow Bot API",
    description="Automated follow bot for FreeFire with multi-format account support",
    version="1.0.0",
    lifespan=lifespan
)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- API Endpoints ----------
@app.get("/")
@app.get("/health")
async def health_check():
    token_manager: TokenManager = app.state.token_manager
    accounts = load_accounts(Config.ACCOUNTS_FILE)
    return {
        "status": "ok",
        "tokens_cached": token_manager.get_token_count(),
        "accounts_loaded": len(accounts)
    }

@app.get("/follow")
async def follow_user(target_uid: int = Query(..., description="The UID of the user to follow")):
    try:
        token_manager: TokenManager = app.state.token_manager
        
        tokens = token_manager.get_all_tokens()
        
        if not tokens:
            raise HTTPException(
                status_code=503,
                detail="No JWT tokens available. Please ensure accounts are loaded and tokens are refreshed."
            )
        
        results = []
        success_count = 0
        failed_count = 0
        
        def process_token(jwt: str, idx: int):
            status, content, error = send_follow(jwt, target_uid)
            decoded = decode_response(content) if content else {"error": "No response"}
            
            return {
                "token_index": idx,
                "status_code": status,
                "success": status == 200,
                "response": decoded,
                "error": error
            }
        
        futures = []
        with app.state.executor as executor:
            for idx, jwt in enumerate(tokens):
                future = executor.submit(process_token, jwt, idx)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    if result["success"]:
                        success_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logger.error(f"Error in follow request: {e}")
                    failed_count += 1
        
        return JSONResponse({
            "status": "completed",
            "target_uid": target_uid,
            "total_tokens_used": len(tokens),
            "successful": success_count,
            "failed": failed_count,
            "results": results
        })
    except Exception as e:
        logger.error(f"Error in follow endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/refresh-tokens")
async def refresh_tokens():
    token_manager: TokenManager = app.state.token_manager
    token_manager._refresh_all_tokens()
    return {
        "status": "success",
        "message": "Token refresh initiated",
        "tokens_count": token_manager.get_token_count()
    }

@app.get("/accounts")
async def list_accounts():
    accounts = load_accounts(Config.ACCOUNTS_FILE)
    return {
        "total_accounts": len(accounts),
        "accounts": [{"uid": uid, "password": "***"} for uid, _ in accounts]
    }

@app.get("/tokens")
async def list_tokens():
    token_manager: TokenManager = app.state.token_manager
    return {
        "total_tokens": token_manager.get_token_count(),
        "token_summary": [
            {
                "uid": uid,
                "last_refresh": data.get("last_refresh"),
                "has_valid_jwt": bool(data.get("jwt"))
            }
            for uid, data in token_manager.tokens.items()
        ]
    }

# ---------- Main Entry Point ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
