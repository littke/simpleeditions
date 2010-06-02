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
import os.path
import sys
import time
import traceback
import urllib

from django.utils import simplejson
from google.appengine.api import users
from google.appengine.ext import db, webapp
from google.appengine.ext.webapp import template

import simpleeditions
from simpleeditions import controller, settings, utils

class TemplatedRequestHandler(webapp.RequestHandler):
    """Simplifies handling requests. In particular, it simplifies working
    with templates, with its render() method.

    """

    def __init__(self):
        self._errors = []

    def add_error(self, message):
        """Adds an error message. All errors will be available as the template
        variable "errors".

        """
        self._errors.append(message)

    def do_get_post(self):
        """For handlers that allow a POST to be simulated during a GET request,
        calling this method will take the POST data from a query string
        parameter and add it as POST data.

        This is useful when redirecting between pages, and the target page
        should be POSTed to.

        """
        req = self.request
        post = req.get('post')
        if post:
            req.method = 'POST'
            req.body = base64.b64decode(post)
            self.post()
            return True

    def handle_exception(self, exception, debug_mode):
        """Called if this handler throws an exception during execution.

        """
        logging.exception(exception)

        # Also show a traceback if debug is enabled, or if the currently logged
        # in Google user is an application administrator.
        if debug_mode or users.is_current_user_admin():
            tb = ''.join(traceback.format_exception(*sys.exc_info()))
        else:
            tb = None

        self.render(settings.ERROR_TEMPLATE, traceback=tb)

    def initialize(self, request, response):
        super(TemplatedRequestHandler, self).initialize(request, response)
        self.user = controller.get_user_info(self)

    def not_found(self, template_name=None, **kwargs):
        """Similar to the render() method, but with a 404 HTTP status code.
        Also, the template_name argument is optional. If not specified, the
        NOT_FOUND_TEMPLATE setting will be used instead.

        """
        if not template_name:
            template_name = settings.NOT_FOUND_TEMPLATE
        self.response.set_status(404)
        self.render(template_name, **kwargs)

    def render(self, template_name, **kwargs):
        """Renders the specified template to the output.

        The template will have the following variables available, in addition
        to the ones specified in the render() method:
        - DEBUG: Whether the application is running in debug mode.
        - DOMAIN: The domain of the application.
        - STATIC_PATH: The path under which all static content lies.
        - VERSION: The version of the application.
        - errors: A (possibly empty) list of errors that have occurred.
        - request: The current request object. Has attributes such as 'path',
                   'query_string', etc.

        """
        kwargs.update({'DEBUG': settings.DEBUG,
                       'DOMAIN': settings.DOMAIN,
                       'FACEBOOK_APP_ID': settings.FACEBOOK_APP_ID,
                       'STATIC_PATH': settings.STATIC_PATH,
                       'VERSION': settings.VERSION,
                       'errors': self._errors,
                       'request': self.request,
                       'user': self.user})

        path = os.path.join(settings.TEMPLATE_DIR, template_name)
        self.response.out.write(template.render(path, kwargs))


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
            urllib.quote_plus(req.get('continue', '/')),
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
        if self.user:
            return func(self, *args, **kwargs)
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
        res.headers['Content-Type'] = 'application/json'
        res.out.write(simplejson.dumps(result, separators=(',', ':')))

class ArticleHandler(TemplatedRequestHandler):
    def get(self, article_id):
        try:
            article = controller.get_article(self, int(article_id))
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found()
            return

        self.render('article.html',
            article=article,
            page_title=article['title'])

class ArticleRevisionHandler(TemplatedRequestHandler):
    def get(self, article_id, revision):
        try:
            revision = controller.get_revision(self, int(article_id), revision)
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found()
            return

        self.render('article_revision.html',
            revision=revision)

class ArticleRevisionsHandler(TemplatedRequestHandler):
    def get(self, article_id):
        try:
            article = controller.get_article(self, int(article_id))
            revisions = controller.get_revisions(self, int(article_id))
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found()
            return

        self.render('article_revisions.html',
            article=article,
            revisions=revisions)

class ArticlesHandler(TemplatedRequestHandler):
    def get(self):
        self.render('articles.html',
            articles=controller.get_articles(self, "-last_modified", 10, False))

class BlobHandler(webapp.RequestHandler):
    def get(self, blob_key):
        res = self.response

        blob = controller.get_blob(blob_key)
        if not blob:
            res.set_status(404)
            return
        res.headers['Content-Type'] = blob.content_type
        res.out.write(blob.data)

class EditArticleHandler(TemplatedRequestHandler):
    @login_required
    def get(self, article_id):
        try:
            article = controller.get_article(self, int(article_id))
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found()
            return

        self.render('article_edit.html',
            article=article)

    @login_required
    def post(self, article_id):
        try:
            article_id = int(article_id)

            req = self.request
            article = controller.update_article(
                self, article_id, req.get('title'), req.get('content'),
                req.get('icon'), req.get('message'))

            self.redirect('/%d/%s' % (article_id, article['slug']))
            return
        except (TypeError, ValueError):
            logging.exception('Presumed browser sent erroneous values:')
            self.add_error('Your browser sent invalid values.')
        except simpleeditions.SaveArticleError, e:
            self.add_error(e.message)

        # Some kind of error has occurred; show the edit page again.
        self.get(article_id)

class HomeHandler(TemplatedRequestHandler):
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
            articles=articles)

class LoginHandler(TemplatedRequestHandler):
    def get(self):
        if self.do_get_post():
            return

        self.render('login.html')

    def post(self):
        if not do_auth(self, controller.log_in):
            return

        # User successfully logged in.
        redirect_to = self.request.get('continue', '/')
        self.redirect(redirect_to)

class LogOutHandler(TemplatedRequestHandler):
    def get(self):
        controller.log_out(self)

        redirect_to = self.request.get('continue', '/')
        self.redirect(redirect_to)

class NewArticleHandler(TemplatedRequestHandler):
    @login_required
    def get(self):
        self.render('article_new.html')

    @login_required
    def post(self):
        req = self.request
        try:
            article = controller.create_article(
                self, req.get('title'), req.get('content'), req.get('icon'))

            self.redirect('/%d/%s' % (article['id'], article['slug']))
            return
        except simpleeditions.SaveArticleError, e:
            self.add_error(e.message)

        # Some kind of error has occurred; show the create page again.
        self.get()

class NotFoundHandler(TemplatedRequestHandler):
    def get(self):
        self.not_found()
    post = get

class RegisterHandler(TemplatedRequestHandler):
    def get(self):
        if self.do_get_post():
            return

        self.render('register.html')

    def post(self):
        if not do_auth(self, controller.register):
            return

        # Renew user info, since the user just registered and should be logged
        # in.
        self.user = controller.get_user_info(self)
        self.render('register_success.html')

_static_pages = ['about.html']
class StaticPageHandler(TemplatedRequestHandler):
    def get(self, page_slug):
        page = '%s.html' % page_slug
        if page in _static_pages:
            self.render(page)
        else:
            self.not_found()
