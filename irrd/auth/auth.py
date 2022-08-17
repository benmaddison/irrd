import typing

from imia import (SessionAuthenticator, AuthenticationMiddleware, LoginManager, UserLike,
                  UserProvider)
from sqlalchemy.orm import joinedload
from starlette.middleware import Middleware
from starlette.requests import HTTPConnection

from irrd.storage.models import AuthUser
from . import ORMSessionProvider


class AuthProvider(UserProvider):
    async def find_by_id(self, connection: HTTPConnection, identifier: str) -> typing.Optional[UserLike]:
        session_provider = ORMSessionProvider()
        target = session_provider.session.query(AuthUser).filter_by(email=identifier).options(joinedload('*'))
        user = await session_provider.run(target.one)
        session_provider.session.expunge_all()
        session_provider.commit_close()
        return user

    async def find_by_username(self, connection: HTTPConnection, username_or_email: str) -> typing.Optional[UserLike]:
        return await self.find_by_id(connection, username_or_email)

    async def find_by_token(self, connection: HTTPConnection, token: str) -> typing.Optional[UserLike]:
        return None


class MyPasswordVerifier:
    def verify(self, plain: str, hashed: str) -> bool:
        return hashed == plain


secret_key = 'key!'  # TODO
user_provider = AuthProvider()
password_verifier = MyPasswordVerifier()  # TODO: pick
login_manager = LoginManager(user_provider, password_verifier, secret_key)


authenticators = [
    SessionAuthenticator(user_provider=user_provider),
]

auth_middleware = Middleware(AuthenticationMiddleware, authenticators=authenticators)
