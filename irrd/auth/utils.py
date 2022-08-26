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


def reset_token(user: AuthUser) -> str:
    secret = 'aaaaaa'
    user_key = str(user.pk) + str(user.updated) + user.password
    expiry_day = date.today() + timedelta(days=PASSWORD_RESET_VALIDITY_DAYS)
    expiry_days = expiry_day - PASSWORD_RESET_TOKEN_ROOT
    hash_token = PASSWORD_RESET_SECRET + user_key + str(expiry_days.days)
    digest = hashlib.sha224(hash_token.encode('utf-8')).digest()
    hash = urlsafe_b64encode(digest).decode('ascii')
    return str(expiry_days.days) + '-' + str(hash)


def validate_token(user: AuthUser, token: str) -> bool:
    try:
        expiry_days, encoded_hash = token.split('-', 1)
        user_key = str(user.pk) + str(user.updated) + user.password
        expiry_date = PASSWORD_RESET_TOKEN_ROOT + timedelta(days=int(expiry_days))
        hash_token = PASSWORD_RESET_SECRET + user_key + expiry_days
        token_hash = urlsafe_b64decode(encoded_hash)
        expected_hash = hashlib.sha224(hash_token.encode('utf-8')).digest()
        return expiry_date >= date.today() and secrets.compare_digest(token_hash, expected_hash)
    except ValueError:
        return False
