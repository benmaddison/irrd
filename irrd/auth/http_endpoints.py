from collections import defaultdict

from starlette.requests import Request
from starlette.responses import Response

from irrd.storage.models import AuthUser, RPSLDatabaseObject
from irrd.storage.queries import RPSLDatabaseQuery
from irrd.updates.handler import ChangeSubmissionHandler
from . import (ORMSessionProvider, template_context_render, authentication_required,
               session_provider_manager)


@session_provider_manager
@authentication_required
async def index(request: Request, session_provider: ORMSessionProvider) -> Response:
    # TODO: RPKI state??
    user_mntners = [
        (mntner.rpsl_mntner_pk, mntner.rpsl_mntner_source)
        for mntner in request.auth.user.mntners
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
        for mntner in request.auth.user.mntners:
            mntner_perms[mntner.rpsl_mntner_source].append(mntner.rpsl_mntner_pk)

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


@session_provider_manager
@authentication_required
async def user_detail(request: Request, session_provider: ORMSessionProvider) -> Response:
    # The user detail page needs a rich and bound instance of AuthUser
    query = session_provider.session.query(AuthUser).filter_by(email=request.auth.user.email)
    bound_user = await session_provider.run(query.one)
    return template_context_render('user_detail.html', request, {'user': bound_user})


