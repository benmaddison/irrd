# TODO: find appropriate places for all that ends up here
import hashlib
import secrets
import typing
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import date, timedelta

from starlette.requests import Request

from irrd.storage.models import AuthUser


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
    secret = 'aaaaaa'  # TODO: actual secret key
    user_key = str(user.pk) + str(user.updated) + user.password
    expiry_day = date.today() + timedelta(days=7)  # TODO: configurable days
    expiry_days = expiry_day - date(2022, 1, 1)  # TODO: constant
    hash_token = secret + user_key + str(expiry_days.days)
    digest = hashlib.sha224(hash_token.encode('utf-8')).digest()
    hash = urlsafe_b64encode(digest).decode('ascii')
    return str(expiry_days.days) + '-' + str(hash)


def validate_token(user: AuthUser, token: str) -> bool:
    # TODO: more resiliency for parsing errors
    try:
        secret = 'aaaaaa'  # TODO: actual secret key
        expiry_days, encoded_hash = token.split('-', 1)
        user_key = str(user.pk) + str(user.updated) + user.password
        expiry_date = date(2022, 1, 1) + timedelta(days=int(expiry_days))  # TODO: constant
        hash_token = secret + user_key + expiry_days
        token_hash = urlsafe_b64decode(encoded_hash)
        expected_hash = hashlib.sha224(hash_token.encode('utf-8')).digest()
        return expiry_date >= date.today() and secrets.compare_digest(token_hash,
                                                                      expected_hash)  # TODO: not constant time
    except ValueError:
        return False
