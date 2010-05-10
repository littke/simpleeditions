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

import base64
import datetime
import logging
import time
import urllib

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
            kwargs[str(name)] = value

    # Call the auth function with the requested auth type.
    auth_type = kwargs.pop('auth_type')
    try:
        auth_func(handler, auth_type, **kwargs)
    except simpleeditions.ExternalLoginNeededError:
        # The authentication method requires that the user be directed to an
        # external URL.

        # Create a return path that has the POST data encoded, so that this
        # request can be re-evaluated once the user has logged in to the
        # external service.
        path = '%s?continue=%s&post=%s' % (
            req.path,
            urllib.quote(req.get('continue', '/')),
            base64.b64encode(urllib.urlencode(req.POST)))

        login_url = controller.get_login_url(
            handler,
            auth_type,
            path)
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
    # Return datetimes as a UNIX timestamp (seconds since 1970).
    if isinstance(obj, datetime.datetime):
        return int(time.mktime(obj.timetuple()))

    # Since strings are iterable, return early for them.
    if isinstance(obj, basestring):
        return obj

    # Handle dicts specifically.
    if isinstance(obj, dict):
        new_obj = {}
        for key, value in obj.iteritems():
            new_obj[key] = jsonify(value)
        return new_obj

    # Walk through iterable objects and return a jsonified list.
    try:
        iterator = iter(obj)
    except TypeError:
        # Return non-iterable objects as they are.
        return obj
    else:
        return [jsonify(item) for item in iterator]

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
        # Require that the attribute has been marked as public.
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
            logging.exception('API error:')

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
        user = controller.get_user_info(self)

        try:
            article = controller.get_article(self, int(article_id))
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found(user=user)
            return

        self.render('article.html',
            user=user,
            article=article,
            page_title=article['title'])

class ArticlesHandler(utils.TemplatedRequestHandler):
    def get(self):
        self.render('articles.html',
            user=controller.get_user_info(self),
            articles=controller.get_articles(self, "-last_modified", 10, False))

class EditArticleHandler(utils.TemplatedRequestHandler):
    @login_required
    def get(self, user, article_id, errors=None):
        try:
            article = controller.get_article(self, int(article_id))
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found(user=controller.get_user_info(self))
            return

        self.render('article_edit.html',
            user=user, article=article, errors=errors)

    @login_required
    def post(self, user, article_id):
        errors = []

        try:
            article_id = int(article_id)

            req = self.request
            article = controller.update_article(
                self, article_id, req.get('title'), req.get('content'),
                req.get('message'))
            self.redirect('/%d/%s' % (article_id, article['slug']))
            return
        except (TypeError, ValueError):
            errors.append('Your browser sent invalid values.')
        except simpleeditions.SaveArticleError, e:
            errors.append(e.message)
        except:
            errors.append('An unexpected error occurred. You could try again, '
                          'or wait for the administrators to look into the '
                          'error (it has been logged).')
            logging.exception('Unexpected error when editing article:')

        # If this part of the code is reached, something went wrong. Do
        # whatever the GET handler does, and give the template any errors to
        # be displayed.
        self.get(article_id, errors)

class HomeHandler(utils.TemplatedRequestHandler):
    def get(self):
        # Get all recent articles
        articles = controller.get_articles(
            self, order="-created", limit=5, include_content=True)

        # Only show the first part of the article's content.
        # Currently stripping at the "<!--more-->" tag, until we decide
        # on a markdown standard for this tag.
        for article in articles:
            pos = article['html'].find('<!--more-->')
            article['html'] = article['html'][:pos]

        self.render('home.html',
            articles=articles,
            user=controller.get_user_info(self))

class LoginHandler(utils.TemplatedRequestHandler):
    def get(self):
        if self.do_get_post():
            return

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
    def get(self, user, errors=None):
        self.render('article_new.html', user=user, errors=errors)

    @login_required
    def post(self, user):
        errors = []

        req = self.request
        try:
            article = controller.create_article(
                self, req.get('title'), req.get('content'))
            self.redirect('/%d/%s' % (article['id'], article['slug']))
            return
        except simpleeditions.SaveArticleError, e:
            errors.append(e.message)
        except:
            errors.append('An unexpected error occurred. You could try again, '
                          'or wait for the administrators to look into the '
                          'error (it has been logged).')
            logging.exception('Unexpected error when creating article:')

        # If this part of the code is reached, something went wrong. Do
        # whatever the GET handler does, and give the template any errors to
        # be displayed.
        self.get(errors)

class NotFoundHandler(utils.TemplatedRequestHandler):
    def get(self):
        self.not_found(user=controller.get_user_info(self))
    post = get

class RegisterHandler(utils.TemplatedRequestHandler):
    def get(self):
        if self.do_get_post():
            return

        self.render('register.html',
            user=controller.get_user_info(self))

    def post(self):
        if not do_auth(self, controller.register):
            return

        self.render('register_success.html',
            user=controller.get_user_info(self))
