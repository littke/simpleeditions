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

import datetime
import time

from django.utils import simplejson
from google.appengine.ext import db, webapp

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

def login_required(func):
    """A decorator that ensures that the user is logged in to the application.

    The decorator may only be applied to the get/head/post/etc. methods of a
    TemplatedRequestHandler instance.

    If the user is not logged in, a "Not logged in" message will be shown,
    encouraging the user to log in.

    To avoid losing the user object which is fetched to check whether the
    user is logged in, it is added as the first argument (after the self
    argument) to the function.

    """
    def wrapper(self, *args, **kwargs):
        user = controller.get_user_info(self)
        if user:
            return func(self, user, *args, **kwargs)
        self.response.set_status(403)
        self.render('not_logged_in.html')
    return wrapper

def jsonify(obj):
    """Takes complex data structures and returns them as data structures that
    simplejson can handle.

    """
    if isinstance(obj, datetime.datetime):
        return int(time.mktime(obj.timetuple()))

    if isinstance(obj, db.Model):
        o = {'id': obj.key().id_or_name()}
        for name in obj.properties():
            o[name] = jsonify(getattr(obj, name))
        return o

    return obj

class ApiHandler(webapp.RequestHandler):
    """Opens up the controller module to HTTP requests. Arguments should be
    JSON encoded. Result will be JSON encoded.

    """
    def get(self, action):
        res = self.response

        # Attempt to get the attribute in the controller module.
        attr = getattr(controller, action, None)
        if not attr:
            res.set_status(404)
            res.out.write('{"status":"not_found"}')
            return
        if not getattr(attr, '__public', False):
            res.set_status(403)
            res.out.write('{"status":"forbidden"}')
            return

        req = self.request

        try:
            # Build a dict of keyword arguments from the request parameters.
            # All arguments beginning with an underscore will be ignored.
            kwargs = {}
            for arg in req.arguments():
                if arg.startswith('_'): continue
                kwargs[str(arg)] = simplejson.loads(req.get(arg))

            data = attr(self, **kwargs) if callable(attr) else attr
            result = {'status': 'success',
                      'response': jsonify(data)}
        except BaseException, e:
            res.set_status(500)
            result = {'status': 'error',
                      'response': str(e),
                      'module': type(e).__module__,
                      'type': type(e).__name__}

        # Write the response as JSON.
        res.headers['Content-type'] = 'application/json'
        res.out.write(simplejson.dumps(result, separators=(',', ':')))

class ArticleHandler(utils.TemplatedRequestHandler):
    def get(self, article_id):
        try:
            article = controller.get_article(self, int(article_id))
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found(user=controller.get_user_info(self))
            return

        self.render('article.html',
            user=controller.get_user_info(self),
            article=article,
            page_title=article.title)

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
        redirect_to = self.request.get('continue', '/')
        self.redirect(redirect_to)

class LogOutHandler(utils.TemplatedRequestHandler):
    def get(self):
        controller.log_out(self)

        redirect_to = self.request.get('continue', '/')
        self.redirect(redirect_to)

class NewArticleHandler(utils.TemplatedRequestHandler):
    @login_required
    def get(self, user):
        self.render('article_new.html',
            user=user)

    @login_required
    def post(self, user):
        req = self.request
        article = controller.create_article(
            self, req.get('title'), req.get('content'))
        self.redirect('/%d/%s' % (article.key().id(), article.slug))

class RegisterHandler(utils.TemplatedRequestHandler):
    def get(self):
        self.render('register.html',
            user=controller.get_user_info(self))

    def post(self):
        if not do_auth(self, controller.register):
            return

        self.render('register_success.html',
            user=controller.get_user_info(self))
