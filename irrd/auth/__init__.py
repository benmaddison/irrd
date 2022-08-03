import functools
from pathlib import Path

import sqlalchemy.orm as saorm
from asgiref.sync import sync_to_async
from psycopg2 import DatabaseError
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.templating import Jinja2Templates

import irrd
from irrd.conf import get_setting
from irrd.storage.database_handler import DatabaseHandler

templates = Jinja2Templates(directory=Path(__file__).parent / 'templates')

templates.env.globals["irrd_version"] = irrd.__version__


class ORMSessionProvider:
    def __init__(self):
        self.database_handler = DatabaseHandler()
        self.session = self._get_session()

    def _get_session(self):
        return saorm.Session(bind=self.database_handler._connection)

    def get_database_handler(self):
        if not self.database_handler:
            self.database_handler = DatabaseHandler()
        return self.database_handler

    def commit_close(self):
        self.session.commit()
        self.database_handler.commit()
        self.session.close()
        self.database_handler.close()

    @sync_to_async
    def run(self, target):
        try:
            return target()
        except saorm.exc.NoResultFound:
            return None
        except (SQLAlchemyError, DatabaseError):
            self.get_database_handler().refresh_connection()
            target.__self__.session = self.session = self._get_session()
            return target()


def session_provider_manager(func):
    @functools.wraps(func)
    async def endpoint_wrapper(*args, **kwargs):
        provider = ORMSessionProvider()
        response = await func(*args, session_provider=provider, **kwargs)
        provider.commit_close()
        return response

    return endpoint_wrapper


def authentication_required(func):
    @functools.wraps(func)
    async def endpoint_wrapper(*args, **kwargs):
        request = next((arg for arg in list(args) + list(kwargs.values()) if isinstance(arg, Request)), None)

        if not request.auth.is_authenticated:
            # TODO: Implement proper redirect logic
            return RedirectResponse(request.url_for('ui:login'), status_code=302)

        # pass on request
        return await func(*args, **kwargs)

    return endpoint_wrapper


def template_context_render(template_name, request, context):
    context['auth_sources'] = [
        name
        for name, settings in get_setting('sources').items()
        if settings.get('authoritative')
    ]

    context['request'] = request
    return templates.TemplateResponse(template_name, context)
