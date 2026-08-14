import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # API Configuration
    BMW_API_URL = os.getenv("BMW_API_URL", "http://187.127.175.208:5001/Bmw")
    FOLLOW_ENDPOINT = "https://client.ind.freefiremobile.com/Follow"
    
    # AES Configuration
    AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    
    # Headers
    HEADERS_TEMPLATE = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1"
    }
    
    # Token refresh interval (4 hours in seconds)
    TOKEN_REFRESH_INTERVAL = 4 * 3600
    
    # Thread pool settings
    MAX_WORKERS = 20
    
    # Retry settings
    JWT_RETRIES = 3
    FOLLOW_RETRIES = 2
    
    # File paths
    ACCOUNTS_FILE = "accounts.txt"
    TOKENS_FILE = "tokens.json"
