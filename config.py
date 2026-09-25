# config.py
import os
from enum import Enum
from dataclasses import dataclass

class Environment(Enum):
    SANDBOX = "sandbox"
    LIVE = "live"

@dataclass
class ReloadlyCredentials:
    client_id: str
    client_secret: str
    environment: Environment
    base_url: str = ""
    auth_url: str = ""
    audience: str = ""

    @classmethod
    def from_env(cls):
        env = os.getenv('RELOADLY_ENVIRONMENT', 'sandbox').lower()
        environment = Environment.SANDBOX if env == 'sandbox' else Environment.LIVE

        client_id = os.getenv('RELOADLY_CLIENT_ID', '').strip()
        client_secret = os.getenv('RELOADLY_CLIENT_SECRET', '').strip()

        if environment == Environment.SANDBOX:
            base_url = "https://topups-sandbox.reloadly.com"
            auth_url = "https://auth.reloadly.com/oauth/token"
            audience = "https://topups-sandbox.reloadly.com"
        else:
            base_url = "https://topups.reloadly.com"
            auth_url = "https://auth.reloadly.com/oauth/token"
            audience = "https://topups.reloadly.com"

        return cls(
            client_id=client_id,
            client_secret=client_secret,
            environment=environment,
            base_url=base_url,
            auth_url=auth_url,
            audience=audience
        )