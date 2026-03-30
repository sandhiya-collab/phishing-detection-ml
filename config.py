# config.py
import os
from dotenv import load_dotenv

# Force load .env file with absolute path
dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(dotenv_path, override=True)

print(f"Loading .env from: {dotenv_path}")
print(f"DEEPSEEK_API_KEY exists: {bool(os.getenv('DEEPSEEK_API_KEY'))}")

# ==============================
# DATABASE CONFIGURATION
# ==============================
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'phishguard_user'),
    'password': os.getenv('DB_PASSWORD', 'sandhiya@44'),
    'database': os.getenv('DB_NAME', 'phishguard'),
    'port': int(os.getenv('DB_PORT', 3306))
}

# MySQL connection string for SQLAlchemy
SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}?charset=utf8mb4"

# ==============================
# DEEPSEEK CONFIGURATION
# ==============================
try:
    from pydantic_settings import BaseSettings
    from pydantic import Field

    class Settings(BaseSettings):
        DEEPSEEK_API_KEY: str = Field("", env="DEEPSEEK_API_KEY")
        DEEPSEEK_API_URL: str = "https://api.deepseek.com/v1/chat/completions"
        DEEPSEEK_MODEL: str = "deepseek-chat"
        REQUEST_TIMEOUT: int = 30
        MAX_TOKENS: int = 1500
        TEMPERATURE: float = 0.1
        MAX_TEXT_LENGTH: int = 5000
        CACHE_SIZE: int = 100

        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            extra = "ignore"

    settings = Settings()
    PYDANTIC_AVAILABLE = True

except ImportError:
    try:
        from pydantic import BaseSettings, Field

        class Settings(BaseSettings):
            DEEPSEEK_API_KEY: str = Field("", env="DEEPSEEK_API_KEY")
            DEEPSEEK_API_URL: str = "https://api.deepseek.com/v1/chat/completions"
            DEEPSEEK_MODEL: str = "deepseek-chat"
            REQUEST_TIMEOUT: int = 30
            MAX_TOKENS: int = 1500
            TEMPERATURE: float = 0.1
            MAX_TEXT_LENGTH: int = 5000
            CACHE_SIZE: int = 100

            class Config:
                env_file = ".env"
                env_file_encoding = "utf-8"

        settings = Settings()
        PYDANTIC_AVAILABLE = True

    except ImportError:
        class Settings:
            DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
            DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
            DEEPSEEK_MODEL = "deepseek-chat"
            REQUEST_TIMEOUT = 30
            MAX_TOKENS = 1500
            TEMPERATURE = 0.1
            MAX_TEXT_LENGTH = 5000
            CACHE_SIZE = 100

        settings = Settings()
        PYDANTIC_AVAILABLE = False

# Force override with direct os.getenv as fallback
if not settings.DEEPSEEK_API_KEY:
    settings.DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")

config = settings

# ==============================
# RUNTIME VALIDATION
# ==============================

def is_deepseek_enabled() -> bool:
    """
    DeepSeek is enabled ONLY if API key exists and is not empty.
    """
    enabled = bool(config.DEEPSEEK_API_KEY and config.DEEPSEEK_API_KEY.strip())
    print(f"DeepSeek Enabled: {enabled} - Key length: {len(config.DEEPSEEK_API_KEY.strip()) if config.DEEPSEEK_API_KEY else 0}")
    return enabled