from functools import partial

from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError, OAuth2Error
from flask import (
    redirect,
    url_for,
    Response,
    abort,
    session,
)

from flask.globals import LocalProxy, _lookup_app_object
try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack
from flask_dance.consumer import OAuth2ConsumerBlueprint

from .auth import Auth


okta = LocalProxy(partial(_lookup_app_object, "okta_oauth"))


class OktaOAuth(Auth):
    def __init__(self, app, unprotected_view_functions, base_url):
        super(OktaOAuth, self).__init__(app, unprotected_view_functions)
        scope = ["openid", "email", "profile"]
        okta_bp = OAuth2ConsumerBlueprint(
            "okta",
            __name__,
            scope=scope,
            base_url=base_url,
            token_url=base_url + '/oauth2/v1/token',
            authorization_url=base_url + '/oauth2/v1/authorize'
        )
        okta_bp.from_config["client_id"] = "OKTA_OAUTH_CLIENT_ID"
        okta_bp.from_config["client_secret"] = "OKTA_OAUTH_CLIENT_SECRET"

        @okta_bp.before_app_request
        def set_applocal_session():
            ctx = stack.top
            ctx.okta_oauth = okta_bp.session

        app.server.register_blueprint(okta_bp, url_prefix="/login")

    def is_authorized(self):
        if not okta.authorized:
            # send to okta login
            return False

        try:
            resp = okta.get("/oauth2/v1/userinfo")
            assert resp.ok, resp.text

            session['email'] = resp.json().get('email')
            return True
        except (InvalidGrantError, TokenExpiredError):
            return self.login_request()

    def login_request(self):
        # send to okta auth page
        return redirect(url_for("okta.login"))

    def auth_wrapper(self, f):
        def wrap(*args, **kwargs):
            if not self.is_authorized():
                return Response(status=403)

            response = f(*args, **kwargs)
            return response
        return wrap

    def index_auth_wrapper(self, original_index):
        def wrap(*args, **kwargs):
            if self.is_authorized():
                return original_index(*args, **kwargs)
            else:
                return self.login_request()
        return wrap
