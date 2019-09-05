# -*- coding: utf-8 -*-
# Copyright 2018 ACSONE SA/NV
# Copyright 2017, XOE Corp.
# @author Deiber Rincon <dri@xoe.solutions>
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).

# Stdlib:
import secrets
from datetime import timedelta

# Odoo:
from odoo import _, api, fields, models  # noqa


class Token(models.Model):
    """
    Model that stores the token authentication for classes,
    that means not only users. This can be useful for integrate
    Odoo with other platforms
    """
    _name = "authentication.token"
    _description = "Token authentication for objects"

    res_class_name = fields.Char(
        help="The resouce class name"
    )
    res_id = fields.Integer(help="The resource id")
    token = fields.Char(compute="_compute_token", store=True)
    expires = fields.Boolean(default=True)
    expiration_interval_days = fields.Integer(
        default=30, help="Interval of days for token expiration"
    )
    expiration_date = fields.Datetime(compute="_compute_expiration_date")
    creation_date = fields.Datetime()

    @api.multi
    @api.depends("res_class_name","res_id")
    def _compute_token(self):
        """Compute multiple tokens"""
        for token in self:
            token.token = self._generate_token()

    @api.multi
    @api.depends("expires")
    def _compute_expiration_date(self):
        """Compute the expiration and creation date of tokens"""
        for token in self:
            if token.expires:
                token.write({
                    "expiration_date": fields.datetime.now() + timedelta(days=self.expiration_interval_days),
                    "creation_date": fields.datetime.now()
                })

    @staticmethod
    def _generate_token():
        """Return generated token"""
        return secrets.token_urlsafe(20)

    def _check_token(self):
        """
        Check if the token is valid according to expiration_date
        """
        self.ensure_one()
        if self.expires:
            if (fields.datetime.now() - self.expiration_date).days < 0:
                return False
        return True

    @api.multi
    def renew_token(self):
        """Renew tokens"""
        for token in self:
            token.token = self._generate_token()
        self._compute_expiration_date()

    _sql_constraints = [
        (
            "res_class_name_res_id_token_uniq",
            "unique (res_class_name, res_id, token)",
            "Only one token per object is allowed"
        )
    ]
