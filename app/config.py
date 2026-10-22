from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    
    NEO4J_URI: str ="bolt://127.0.0.1:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = ""
    NEO4J_DATABASE: str = "neo4j"

    REDIS_ENABLED: bool = False
    REDIS_URL: str = "redis://localhost:6379/0"

    SECRET_KEY: str = "change-this-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"

    ANALYST_USERNAME: str = "analyst"
    ANALYST_PASSWORD: str = "analyst123"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()