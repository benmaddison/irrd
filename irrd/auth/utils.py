import hashlib
import secrets
import typing
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import date, timedelta

from starlette.requests import Request

from irrd.storage.models import AuthUser

PASSWORD_RESET_TOKEN_ROOT = date(2022, 1, 1)
PASSWORD_RESET_SECRET = 'aaaaa'
PASSWORD_RESET_VALIDITY_DAYS = 7


# From https://github.com/accent-starlette/starlette-core/
def message(request: Request, message: typing.Any, category: str = "success") -> None:
    if category not in ["info", "success", "danger", "warning"]:
        raise ValueError(f"Unknown category: {category}")
    if "_messages" not in request.session:
        request.session["_messages"] = []
    request.session["_messages"].append({"message": message, "category": category})


# From https://github.com/accent-starlette/starlette-core/
def get_messages(request: Request):
    return request.session.pop("_messages") if "_messages" in request.session else []


class AuthUserToken:
    def __init__(self, user):
        self.user_key = str(user.pk) + str(user.updated) + user.password

    def generate_token(self) -> str:
        expiry_date = date.today() + timedelta(days=PASSWORD_RESET_VALIDITY_DAYS)
        expiry_days = expiry_date - PASSWORD_RESET_TOKEN_ROOT

        hash_str = urlsafe_b64encode(self._hash(expiry_days.days)).decode('ascii')
        return str(expiry_days.days) + '-' + hash_str

    def validate_token(self, token: str) -> bool:
        try:
            expiry_days, input_hash_encoded = token.split('-', 1)
            expiry_date = PASSWORD_RESET_TOKEN_ROOT + timedelta(days=int(expiry_days))

            expected_hash = self._hash(expiry_days)
            input_hash = urlsafe_b64decode(input_hash_encoded)

            return expiry_date >= date.today() and secrets.compare_digest(input_hash, expected_hash)
        except ValueError:
            return False

    def _hash(self, expiry_days: int) -> bytes:
        hash_data = PASSWORD_RESET_SECRET + self.user_key + str(expiry_days)
        return hashlib.sha224(hash_data.encode('utf-8')).digest()
