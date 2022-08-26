import secrets

import wtforms
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette_wtf import StarletteForm, csrf_protect
from wtforms_bootstrap5 import RendererContext

from . import template_context_render, ORMSessionProvider, session_provider_manager, templates
from .auth import login_manager
from .utils import AuthUserToken, message
from ..storage.models import AuthUser


async def login(request: Request):
    if request.method == 'GET':
        return template_context_render('login.html', request, {
            'errors': None,
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


class CreateAccountForm(StarletteForm, wtforms.Form):
    def __init__(self, *args, session_provider: ORMSessionProvider, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_provider = session_provider

    email = wtforms.EmailField(
        "Your email address",
        validators=[wtforms.validators.DataRequired()],
    )
    name = wtforms.StringField(
        "Your name",
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Create account")

    async def validate(self, extra_validators=None):
        valid = await super().validate(extra_validators)
        if not valid:
            return False

        query = self.session_provider.session.query(AuthUser).filter_by(email=self.email.data)
        if await self.session_provider.run(query.count):
            self.email.errors.append('Account already exists.')
            return False

        return True


@csrf_protect
@session_provider_manager
async def create_account(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await CreateAccountForm.from_formdata(request=request, session_provider=session_provider)
    context = RendererContext()
    if not form.is_submitted() or not await form.validate():
        form_html = context.render(form)
        return template_context_render(
            'create_account_form.html', request, {'form_html': form_html}
        )

    new_user = AuthUser(
        email=form.email.data,
        password=secrets.token_hex(24),
        name=form.name.data,
    )
    session_provider.session.add(new_user)
    session_provider.session.commit()

    token = AuthUserToken(new_user).generate_token()
    email_body = templates.get_template('create_account_mail.txt').render(user_pk=new_user.pk, request=request, token=token)
    print(email_body)
    message(request, f'You have been sent an email to confirm your account on {form.email.data}.')
    return RedirectResponse(request.url_for('ui:index'), status_code=302)


class ResetPasswordForm(StarletteForm, wtforms.Form):
    email = wtforms.EmailField(
        "Your email address",
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Reset password")


@csrf_protect
@session_provider_manager
async def reset_password(request: Request, session_provider: ORMSessionProvider) -> Response:
    form = await ResetPasswordForm.from_formdata(request=request)
    if not form.is_submitted() or not await form.validate():
        context = RendererContext()
        form_html = context.render(form)
        return template_context_render(
            'reset_password_form.html', request, {'form_html': form_html}
        )

    query = session_provider.session.query(AuthUser).filter_by(email=form.email.data)
    user = await session_provider.run(query.one)

    if user:
        token = AuthUserToken(user).generate_token()
        email_body = templates.get_template('reset_password_mail.txt').render(user_pk=user.pk, request=request, token=token)
        print(email_body)
    message(request, f'You have been sent an email to reset your password on {form.email.data}, if this account exists.')
    return RedirectResponse(request.url_for('ui:index'), status_code=302)


class SetPasswordForm(StarletteForm, wtforms.Form):
    new_password = wtforms.PasswordField(
        validators=[wtforms.validators.DataRequired()],
    )
    new_password_confirmation = wtforms.PasswordField(
        validators=[wtforms.validators.DataRequired()],
    )
    submit = wtforms.SubmitField("Set password")

    async def validate(self, extra_validators=None):
        valid = await super().validate(extra_validators)
        if not valid:
            return False

        if self.new_password.data != self.new_password_confirmation.data:
            self.new_password_confirmation.errors.append('Passwords do not match.')
            return False

        return True


@csrf_protect
@session_provider_manager
async def set_password(request: Request, session_provider: ORMSessionProvider) -> Response:
    query = session_provider.session.query(AuthUser).filter(
        AuthUser.pk == request.path_params['pk'],
    )
    user = await session_provider.run(query.one)

    if not user or not AuthUserToken(user).validate_token(request.path_params['token']):
        return Response(status_code=404)

    # get user and check token
    # session_provider.session.add(new_user)
    form = await SetPasswordForm.from_formdata(request=request)
    context = RendererContext()
    if not form.is_submitted() or not await form.validate():
        form_html = context.render(form)
        return template_context_render(
            'create_account_confirm_form.html', request,
            {'form_html': form_html, 'initial': request.path_params.get('initial')}
        )

    user.password = form.new_password.data
    session_provider.session.add(user)
    message(request, 'Your password has been changed.')
    return RedirectResponse(request.url_for('ui:login'), status_code=302)
