from pydantic_settings import BaseSettings
from typing import Dict
from pydantic import HttpUrl

class Settings(BaseSettings):
    ISSUER: str
    CLIENT_ID: str
    CLIENT_SECRET: str
    REDIRECT_URI: HttpUrl
    SUBJECT: str = "example"
    SSL_KEYFILE: str
    SSL_CERTFILE: str
    HOST: str = "0.0.0.0"
    PORT: int = 443

    class Config:
        env_file = ".env"

    @property
    def CLIENTS(self) -> Dict:
        return {
            self.CLIENT_ID: {
                "client_secret": self.CLIENT_SECRET,
                "redirect_uris": [str(self.REDIRECT_URI)],
                "grant_types": ["authorization_code"],
                "response_types": ["code"]
            }
        }

settings = Settings()
