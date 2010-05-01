# -*- coding: utf-8 -*-
#
# Copyright © 2010 Jonatan Littke
#
# This file is part of SimpleEditions.
#
# SimpleEditions is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# SimpleEditions is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# SimpleEditions. If not, see http://www.gnu.org/licenses/.
#

import simpleeditions
from simpleeditions import controller, settings, utils

def do_auth(handler, auth_func, *args):
    """Performs authentication based on the available form values.

    This function expects at least auth_type to be defined as a form value.

    Returns True when authentication succeeded and False when authentication
    failed but the handler has been redirected to another URL where the
    authentication can be completed. In other cases, an exception is raised.

    """
    req = handler.request

    # Build a argument dictionary used to call the authentication function.
    kwargs = {}
    for name, value in req.POST.items():
        if not name.startswith('_') and value:
            kwargs[name] = value

    # Call the auth function with the requested auth type.
    auth_type = kwargs.pop('auth_type')
    try:
        auth_func(handler, auth_type, **kwargs)
    except simpleeditions.ExternalLoginNeededError:
        # The authentication method requires that the user be directed to an
        # external URL.
        login_url = controller.get_login_url(
            handler,
            auth_type,
            handler.request.path)
        handler.redirect(login_url)
        return False

    return True

class HomeHandler(utils.TemplatedRequestHandler):
    def get(self):
        self.render('home.html',
            user=controller.get_user_info(self))

class LoginHandler(utils.TemplatedRequestHandler):
    def get(self):
        self.render('login.html',
            user=controller.get_user_info(self))

    def post(self):
        if not do_auth(self, controller.log_in):
            return

        # User successfully logged in.
        self.redirect('/')

class LogOutHandler(utils.TemplatedRequestHandler):
    def get(self):
        controller.log_out(self)
        self.redirect('/')

class RegisterHandler(utils.TemplatedRequestHandler):
    def get(self):
        self.render('register.html',
            user=controller.get_user_info(self))

    def post(self):
        if not do_auth(self, controller.register):
            return

        self.render('register_success.html',
            user=controller.get_user_info(self))
