# -*- coding: utf-8 -*-
# Copyright 2018 ACSONE SA/NV
# Copyright 2017, XOE Corp.
# @author Deiber Rincon <dri@xoe.solutions>
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).

# Stdlib:
import logging
import werkzeug

# Odoo:
from odoo import _, http, models
from odoo.exceptions import AccessDenied
from odoo.addons.base_rest.http import make_json_response
from odoo.http import request, Response
from odoo import SUPERUSER_ID


_logger = logging.getLogger(__name__)


class ResIrHttp(models.AbstractModel):
    _inherit = "ir.http"

    _default_token_keys = ["Bearer ", "Token "]
    _default_auth_token_headers = [
        "HTTP_TOKEN",
        "HTTP_AUTHORIZATION",
        "HTTP_AUTHORIZATION_TOKEN",
    ]

    @staticmethod
    def _default_user_class_name():
        return "res.users"

    @classmethod
    def _auth_method_token(cls):
        """
        Method designed for authenticate objects via token
        """
        msg = _("Token missing, Aacess denied")
        token = cls._get_request_auth_token(request, cls._get_default("auth_token_headers"))
        if token:
            for key in cls._get_default("token_keys"):
                token = token.replace(key,"")

            request.uid = SUPERUSER_ID
            auth_token = request.env["authentication.token"].search([("token", "=", token)])
            if auth_token:
                if auth_token._check_token():
                    request._env = None
                    request.auth_token = auth_token.token
                    if auth_token.res_class_name == cls._default_user_class_name():
                        request.uid = auth_token.res_id
                    return True

                msg = _("Expired token, access denied")
            msg = _("Invalid token, access denied")
        _logger.error(msg)
        return make_json_response(request, data={"error": msg}, status_code=401)

    @classmethod
    def _get_default(cls, key):
        """
        Return the specific default attribute of the class
        """
        return getattr(cls, f"_default_{key}")


    @staticmethod
    def _get_request_auth_token(request, headers_list):
        """
        Return token header contained in the request
        params:
        - request: request
        - headers_list: the list of possible tokens headers in a request
        """
        headers = request.httprequest.environ
        token = [headers.get(h) for h in headers_list if headers.get(h, None)]
        if token:
            return token[0]
        return None

    @classmethod
    def _authenticate(cls, auth_method='user'):
        """Uverride original authenticate method to identify if the return of auth
        method return a response"""
        try:
            if request.session.uid:
                try:
                    request.session.check_security()
                    # what if error in security.check()
                    #   -> res_users.check()
                    #   -> res_users._check_credentials()
                except (AccessDenied, http.SessionExpiredException):
                    # All other exceptions mean undetermined status (e.g. connection pool full),
                    # let them bubble up
                    request.session.logout(keep_db=True)
            if request.uid is None:

                r = getattr(cls, "_auth_method_%s" % auth_method)()
                if isinstance(r, Response):
                    return r

        except (AccessDenied, http.SessionExpiredException, werkzeug.exceptions.HTTPException):
            raise
        except Exception:
            _logger.info("Exception during request Authentication.", exc_info=True)
            raise AccessDenied()
        return auth_method

    @classmethod
    def _dispatch(cls):
        """
        Override original dispatch to idenfity if the authenticate method
        directly return a response
        """
        try:
            rule, arguments = cls._find_handler(return_rule=True)
            func = rule.endpoint
        except werkzeug.exceptions.NotFound as e:
            return cls._handle_exception(e)

        # check authentication level
        try:
            auth_method = cls._authenticate(func.routing["auth"])
            # checking the return of cls._authenticate method
            if isinstance(auth_method, Response):
                return auth_method
        except Exception as e:
            return cls._handle_exception(e)

        return super()._dispatch()
