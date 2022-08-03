import secrets
from collections import defaultdict

import wtforms
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
from starlette_wtf import csrf_protect, StarletteForm
from wtforms_bootstrap5 import RendererContext

from irrd.conf import get_setting, RPSL_MNTNER_AUTH_INTERNAL
from irrd.rpsl.rpsl_objects import RPSLMntner
from irrd.storage.models import AuthMntner, AuthPermission, AuthUser, RPSLDatabaseObject, \
    JournalEntryOrigin
from irrd.storage.queries import RPSLDatabaseQuery
from irrd.updates.handler import ChangeSubmissionHandler
from . import (ORMSessionProvider, template_context_render, authentication_required,
               session_provider_manager)


@session_provider_manager
@authentication_required
async def index(request: Request, session_provider: ORMSessionProvider) -> Response:
    # TODO: RPKI state??
    user_mntners = [
        (perm.mntner.rpsl_mntner_pk, perm.mntner.rpsl_mntner_source)
        for perm in request.auth.user.permissions
    ]
    if not user_mntners:
        return Response('Missing permission', status_code=404)
    user_mntbys, user_sources = zip(*user_mntners)
    q = RPSLDatabaseQuery().lookup_attrs_in(['mnt-by'], user_mntbys).sources(user_sources)
    query_result = session_provider.database_handler.execute_query(q)
    objects = filter(
        lambda obj: any([
            (mntby, obj['source']) in user_mntners
            for mntby in obj['parsed_data']['mnt-by']
        ]),
        query_result,
    )

    return template_context_render('index.html', request, {
        'objects': objects,
        'id': request.auth.user_id,
        'name': request.auth.display_name,
    })


@session_provider_manager
async def rpsl_detail(request: Request, session_provider: ORMSessionProvider):
    if request.method == 'GET':
        if all([key in request.path_params for key in ['rpsl_pk', 'object_class', 'source']]):
            query = session_provider.session.query(RPSLDatabaseObject).filter(
                RPSLDatabaseObject.rpsl_pk == str(request.path_params['rpsl_pk'].upper()),
                RPSLDatabaseObject.object_class == str(request.path_params['object_class'].lower()),
                RPSLDatabaseObject.source == str(request.path_params['source'].upper()),
            )
            rpsl_object = await session_provider.run(query.one)
        else:
            return Response('Missing search parameter', status_code=400)

        return template_context_render('rpsl_detail.html', request, {
            'object': rpsl_object,
        })


# TODO: CSRF?
@session_provider_manager
async def rpsl_update(request: Request, session_provider: ORMSessionProvider) -> Response:
    mntner_perms = defaultdict(list)
    if request.auth.is_authenticated:
        for perm in request.auth.user.permissions:
            mntner_perms[perm.mntner.rpsl_mntner_source].append(perm.mntner.rpsl_mntner_pk)

    if request.method == 'GET':
        existing_data = ''
        if all([key in request.path_params for key in ['rpsl_pk', 'object_class', 'source']]):
            query = session_provider.session.query(RPSLDatabaseObject).filter(
                RPSLDatabaseObject.rpsl_pk == str(request.path_params['rpsl_pk'].upper()),
                RPSLDatabaseObject.object_class == str(request.path_params['object_class'].lower()),
                RPSLDatabaseObject.source == str(request.path_params['source'].upper()),
            )
            obj = await session_provider.run(query.one)
            if obj:
                existing_data = obj.object_text

        return template_context_render('rpsl_form.html', request, {
            'existing_data': existing_data,
            'status': None,
            'report': None,
            'mntner_perms': mntner_perms,
        })

    elif request.method == 'POST':
        # TODO: offload db part to thread
        form_data = await request.form()
        request_meta = {
            'HTTP-client-IP': request.client.host,
            'HTTP-User-Agent': request.headers.get('User-Agent'),
        }

        handler = ChangeSubmissionHandler().load_text_blob(
            object_texts_blob=form_data['data'],
            request_meta=request_meta,
            internal_authenticated_user=request.auth.user if request.auth.is_authenticated else None,
        )
        return template_context_render('rpsl_form.html', request, {
            'existing_data': form_data['data'],
            'status': handler.status(),
            'report': handler.submitter_report_human(),
            'mntner_perms': mntner_perms,
        })
    return Response(status_code=405)  # pragma: no cover


@authentication_required
async def user_detail(request: Request) -> Response:
    return template_context_render('user_detail.html', request, {'user': request.auth.user})


class PermissionAddForm(StarletteForm, wtforms.Form):
    def __init__(self, *args, session_provider: ORMSessionProvider, **kwargs):
        super().__init__(*args, **kwargs)
        self.new_user = None
        self.session_provider = session_provider

    new_user_email = wtforms.EmailField(
        "Email address of the newly authorised user",
        validators=[wtforms.validators.DataRequired()],
    )
    confirm = wtforms.BooleanField(
        "Give this user access to modify all objects maintained by this mntner",
        validators=[wtforms.validators.DataRequired()]
    )
    user_management = wtforms.BooleanField(
        "Give this user access to user management, including adding and removing other users (including myself)",
    )
    submit = wtforms.SubmitField("Authorise this user")

    async def validate(self, extra_validators=None, mntner: AuthMntner=None):
        valid = await super().validate(extra_validators)
        if not valid:
            return False

        query = self.session_provider.session.query(AuthUser).filter_by(email=self.new_user_email.data)
        self.new_user = await self.session_provider.run(query.one)

        if not self.new_user:
            self.new_user_email.errors.append('Unknown user account.')
            return False

        query = self.session_provider.session.query(AuthPermission).filter_by(mntner=mntner, user=self.new_user)
        existing_perms = await self.session_provider.run(query.count)

        if existing_perms:
            self.new_user_email.errors.append('This user already has permissions on this mntner.')
            return False

        return True


@csrf_protect
@session_provider_manager
@authentication_required
async def permission_add(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthMntner).join(AuthPermission)
    query = query.filter(
        AuthMntner.pk == request.path_params['mntner'],
        AuthPermission.user_id == str(request.auth.user.pk),
        AuthPermission.user_management.is_(True),
    )
    mntner = await session_provider.run(query.one)

    if not mntner:
        return Response(status_code=404)

    form = await PermissionAddForm.from_formdata(request=request, session_provider=session_provider)
    context = RendererContext()
    if not form.is_submitted() or not await form.validate(mntner=mntner):
        form_html = context.render(form)
        return template_context_render(
            'permission_form.html', request, {'form_html': form_html, 'mntner': mntner}
        )

    # TODO: require password
    new_permission = AuthPermission(
        user_id=str(form.new_user.pk),
        mntner_id=str(mntner.pk),
        user_management=bool(form.user_management.data),
    )
    session_provider.session.add(new_permission)
    return RedirectResponse(request.url_for('ui:user_detail'), status_code=302)


class PermissionDeleteForm(StarletteForm, wtforms.Form):
    confirm = wtforms.BooleanField(
        "Remove this user's access to this mntner",
        validators=[wtforms.validators.DataRequired()]
    )
    submit = wtforms.SubmitField("Remove this user's authorisation")


@csrf_protect
@session_provider_manager
@authentication_required
async def permission_delete(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthPermission)
    user_mntner_pks = [
        perm.mntner_id
        for perm in request.auth.user.permissions
        if perm.user_management
    ]
    query = query.filter(
        AuthPermission.pk == request.path_params['permission'],
        AuthPermission.mntner_id.in_(user_mntner_pks),
    )
    permission = await session_provider.run(query.one)

    if not permission:
        return Response(status_code=404)

    form = await PermissionDeleteForm.from_formdata(request=request)
    context = RendererContext()
    if not form.is_submitted() or not await form.validate():
        form_html = context.render(form)
        return template_context_render(
            'permission_delete.html', request, {'form_html': form_html, 'permission': permission}
        )

    session_provider.session.query(AuthPermission).filter(
        AuthPermission.pk == request.path_params['permission']
    ).delete()
    session_provider.session.commit()
    session_provider.session.close()
    return RedirectResponse(request.url_for('ui:user_detail'), status_code=302)


class MntnerMigrateInitiateForm(StarletteForm, wtforms.Form):
    def __init__(self, *args, session_provider: ORMSessionProvider, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_provider = session_provider
        self.rpsl_mntner = None
        self.rpsl_mntner_db_pk = None
        auth_sources = [
            name
            for name, settings in get_setting('sources').items()
            if settings.get('authoritative')
        ]
        self.mntner_source.choices = sorted([(source, source) for source in auth_sources])

    mntner_key = wtforms.StringField(
        "Mntner name",
        description="The name (primary key) of the mntner to migrate.",
        validators=[wtforms.validators.DataRequired()],
        filters=[lambda x: x.upper() if x else None],
    )
    mntner_source = wtforms.SelectField(
        "Mntner source",
        description="The RPSL database for your mntner.",
        validators=[wtforms.validators.DataRequired()]
    )
    mntner_password = wtforms.StringField(
        "Mntner password",
        description="One of the current passwords on the mntner",
        validators=[wtforms.validators.DataRequired()]
    )
    confirm = wtforms.BooleanField(
        "I understand that this migration can not be reversed",
        validators=[wtforms.validators.DataRequired()]
    )
    submit = wtforms.SubmitField("Migrate this mntner")

    async def validate(self, extra_validators=None):
        valid = await super().validate(extra_validators)
        if not valid:
            return False

        query = self.session_provider.session.query(RPSLDatabaseObject).outerjoin(AuthMntner)
        query = query.filter(
            RPSLDatabaseObject.rpsl_pk == self.mntner_key.data,
            RPSLDatabaseObject.source == self.mntner_source.data,
            RPSLDatabaseObject.object_class == 'mntner',
        )
        mntner_obj = await self.session_provider.run(query.one)
        if not mntner_obj:
            self.mntner_key.errors.append('Unable to find this mntner object.')
            return False
        if mntner_obj.auth_mntner:
            self.mntner_key.errors.append('This maintainer was already migrated or a migration is in progress.')
            return False
        self.rpsl_mntner_db_pk = mntner_obj.pk
        self.rpsl_mntner = RPSLMntner(mntner_obj.object_text, strict_validation=False)

        if not self.rpsl_mntner.verify_auth(passwords=[self.mntner_password.data]):
            self.mntner_password.errors.append('Invalid password for the methods on this mntner object.')
            return False

        return True


@csrf_protect
@session_provider_manager
@authentication_required
async def mntner_migrate_initiate(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await MntnerMigrateInitiateForm.from_formdata(request=request, session_provider=session_provider)
    context = RendererContext()
    if not form.is_submitted() or not await form.validate():
        form_html = context.render(form)
        return template_context_render(
            'mntner_migrate_initiate.html', request, {'form_html': form_html}
        )

    # TODO: email confirmation
    new_auth_mntner = AuthMntner(
        rpsl_mntner_pk=form.rpsl_mntner.pk(),
        rpsl_mntner_obj_id=str(form.rpsl_mntner_db_pk),
        rpsl_mntner_source=form.mntner_source.data,
        legacy_methods=form.rpsl_mntner.parsed_data['auth'],
        migration_token=secrets.token_urlsafe(24),
    )
    session_provider.session.add(new_auth_mntner)
    session_provider.session.commit()

    new_permission = AuthPermission(
        user_id=str(request.auth.user.pk),
        mntner_id=str(new_auth_mntner.pk),
        user_management=True,
    )
    session_provider.session.add(new_permission)
    return RedirectResponse(request.url_for('ui:user_detail'), status_code=302)


class MntnerMigrateCompleteForm(StarletteForm, wtforms.Form):
    def __init__(self, *args, auth_mntner: AuthMntner, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_mntner = auth_mntner
        self.rpsl_mntner_obj = None

    mntner_password = wtforms.StringField(
        "Mntner password",
        description="One of the current passwords on the mntner",
        validators=[wtforms.validators.DataRequired()]
    )
    confirm = wtforms.BooleanField(
        "I understand that this migration can not be reversed",
        validators=[wtforms.validators.DataRequired()]
    )
    submit = wtforms.SubmitField("Migrate this mntner")

    async def validate(self, extra_validators=None):
        valid = await super().validate(extra_validators)
        if not valid:
            return False

        self.rpsl_mntner_obj = RPSLMntner(self.auth_mntner.rpsl_mntner_obj.object_text, strict_validation=False)
        if not self.rpsl_mntner_obj.verify_auth(passwords=[self.mntner_password.data]):
            self.mntner_password.errors.append('Invalid password for the methods on this mntner object.')
            return False

        return True


@csrf_protect
@session_provider_manager
@authentication_required
async def mntner_migrate_complete(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthMntner).join(AuthPermission)
    query = query.filter(
        AuthMntner.pk == str(request.path_params['pk']),
        AuthMntner.migration_token == request.path_params['token'],
        AuthPermission.user_id == str(request.auth.user.pk),
        AuthPermission.user_management.is_(True),
    )
    auth_mntner = await session_provider.run(query.one)

    if not auth_mntner:
        return Response(status_code=404)
    form = await MntnerMigrateCompleteForm.from_formdata(request=request, auth_mntner=auth_mntner)
    context = RendererContext()
    if not form.is_submitted() or not await form.validate():
        form_html = context.render(form)
        return template_context_render('mntner_migrate_complete.html', request, {
            'form_html': form_html, 'auth_mntner': auth_mntner
        })

    form.auth_mntner.migration_token = None
    session_provider.session.add(form.auth_mntner)

    # TODO: probably move this to RPSLMntner?
    form.rpsl_mntner_obj._update_attribute_value('auth', [RPSL_MNTNER_AUTH_INTERNAL])
    session_provider.database_handler.upsert_rpsl_object(form.rpsl_mntner_obj, origin=JournalEntryOrigin.unknown)

    return RedirectResponse(request.url_for('ui:user_detail'), status_code=302)
