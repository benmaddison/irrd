import typing

from imia import (SessionAuthenticator, AuthenticationMiddleware, LoginManager, UserLike,
                  UserProvider)
from sqlalchemy.orm import joinedload
from starlette.middleware import Middleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import RedirectResponse

from irrd.storage.models import AuthUser
from . import ORMSessionProvider, session_provider_manager, template_context_render


@session_provider_manager
async def login(request: Request):
    if request.method == 'GET':
        return template_context_render('login.html', request, {
            'errors': 'Invalid account or password.',
        })

    if request.method == 'POST':
        data = await request.form()
        email = data['email']
        password = data['password']

        user_token = await login_manager.login(request, email, password)
        if user_token:
            return RedirectResponse(request.url_for('ui:index'), status_code=302)
        else:
            return template_context_render('login.html', request, {
                'errors': 'Invalid account or password.',
            })


async def logout(request: Request):
    await login_manager.logout(request)
    return RedirectResponse(request.url_for('ui:index'), status_code=302)


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
