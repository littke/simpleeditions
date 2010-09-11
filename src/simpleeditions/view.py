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
from datetime import datetime, timedelta
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

class RedirectionNeeded(simpleeditions.Error):
    """Raised when a redirection is needed for an authentication to finish."""

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

    def head(self, *args, **kwargs):
        self.get(*args, **kwargs)

    def initialize(self, request, response):
        super(TemplatedRequestHandler, self).initialize(request, response)
        self.update_user()

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
        - ANALYTICS_TRACKER_ID: The Google Analytics tracker id.
        - DEBUG: Whether the application is running in debug mode.
        - DOMAIN: The domain of the application.
        - FACEBOOK_APP_ID: The Facebook application id.
        - VERSION: The version of the application.
        - errors: A (possibly empty) list of errors that have occurred.
        - request: The current request object. Has attributes such as 'path',
                   'query_string', etc.
        - user: Information about the currently logged in user (if any).

        """
        kwargs.update({'ANALYTICS_TRACKER_ID': settings.ANALYTICS_TRACKER_ID,
                       'DEBUG': settings.DEBUG,
                       'DOMAIN': settings.DOMAIN,
                       'FACEBOOK_APP_ID': settings.FACEBOOK_APP_ID,
                       'VERSION': settings.VERSION,
                       'errors': self._errors,
                       'request': self.request,
                       'user': self.user})

        path = os.path.join(settings.TEMPLATE_DIR, template_name)
        self.response.out.write(template.render(path, kwargs))

    def update_user(self):
        # The public API for getting the current user is not used here since
        # we want access to the actual User instance as well as the data dict.
        self.user_obj = controller.get_current_user(self)
        if self.user_obj:
            self.user = controller.get_user_dict(self.user_obj, True)
            logging.info('Logged in user: %s (id: %d)' % (
                self.user_obj.display_name,
                self.user_obj.key().id()))
        else:
            self.user = None


def do_auth(handler, auth_func, *args):
    """Performs authentication based on the available form values.

    This function expects at least auth_type to be defined as a form value.

    Returns result of authentication when it succeeded and raises the exception
    RedirectionNeeded when authentication failed but the handler has been
    redirected to another URL where the authentication can be completed. In
    other cases, an exception explaining the error is raised.

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
        result = auth_func(handler, auth_type, **kwargs)
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
        raise RedirectionNeeded('This page needs to be redirected.')

    return result

def login_required(func):
    """A decorator that ensures that the user is logged in to the application.

    The decorator may only be applied to the get/head/post/etc. methods of a
    TemplatedRequestHandler instance.

    If the user is not logged in, a "Not logged in" message will be shown,
    encouraging the user to log in.

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
    if isinstance(obj, datetime):
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

class ApiHandler(TemplatedRequestHandler):
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

class ArticleFilesHandler(TemplatedRequestHandler):
    def get(self, article_id):
        try:
            article = controller.get_article(self, int(article_id))
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found()
            return

        files = controller.get_files(self, int(article_id))

        user = self.user_obj
        self.render('article_manage_files.html',
            article=article,
            files=files,
            user_can_upload=user and user.can('upload-files') and (
                user.key().id() == article['user_id'] or
                user.can('edit-any-article')))

    def post(self, article_id):
        try:
            article_id = int(article_id)

            req = self.request
            file = req.POST['file']
            name = req.get('name', file.filename)
            blob = controller.add_file(self, article_id, name, file.type,
                                       file.value)
        except (TypeError, ValueError):
            logging.exception('Presumed browser sent erroneous values:')
            self.add_error('Your browser sent invalid values.')
        except simpleeditions.SaveBlobError, e:
            self.add_error(e.message)

        self.get(article_id)

class ArticleHandler(TemplatedRequestHandler):
    def get(self, article_id):
        try:
            article = controller.get_article(self, int(article_id), True, True)
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found()
            return

        user = self.user_obj
        self.render('article.html',
            article=article,
            comments=controller.get_comments(self, int(article_id)),
            user_can_edit=user and (user.key().id() == article['user_id'] or
                                    user.can('edit-any-article')))

    @login_required
    def post(self, article_id):
        req = self.request
        try:
            controller.create_comment(self, int(article_id),
                                      req.get('comment'))
        except (TypeError, ValueError):
            logging.exception('Presumed browser sent erroneous values:')
            self.add_error('Your browser sent invalid values.')
        except simpleeditions.SaveCommentError, e:
            self.add_error(e.message)

        self.get(article_id)

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

        self.render('article_manage_revisions.html',
            article=article,
            revisions=revisions)

class ArticlesHandler(TemplatedRequestHandler):
    def get(self):
        self.render('articles.html',
            articles=controller.get_articles(self, "title", include_content=False))

class BlobHandler(webapp.RequestHandler):
    def get(self, blob_key):
        res = self.response

        blob = controller.get_blob(blob_key)
        if not blob:
            res.set_status(404)
            return

        cache_time = timedelta(days=365)
        expires = datetime.now() + cache_time

        res.headers['Expires'] = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
        res.headers['Cache-Control'] = 'public, max-age=%d' % (
            cache_time.days * 86400 + cache_time.seconds)
        res.headers['Content-Type'] = blob.content_type

        res.out.write(blob.data)

class EditArticleHandler(TemplatedRequestHandler):
    def get(self, article_id):
        try:
            article = controller.get_article(self, int(article_id), True)
        except (TypeError, ValueError, simpleeditions.NotFoundError):
            self.not_found()
            return

        user = self.user_obj
        self.render('article_manage_edit.html',
            article=article,
            user_can_edit=user and (user.key().id() == article['user_id'] or
                                    user.can('edit-any-article')))

    @login_required
    def post(self, article_id):
        try:
            article_id = int(article_id)

            req = self.request
            article = controller.update_article(
                self, article_id, req.get('title'), req.get('description'),
                req.get('content'), req.get('icon'), req.get('message'))

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
        recent_articles = controller.get_articles(self, order='-published_date', limit=4)
        popular_articles = controller.get_articles(self, order='-views', limit=4)

        self.render('home.html',
            popular_articles=popular_articles,
            recent_articles=recent_articles)

class RecentHandler(TemplatedRequestHandler):
    def get(self):
        articles = controller.get_articles(self, order='-published_date', limit=30)

        self.render('recent.html',
            articles=articles)

class PopularHandler(TemplatedRequestHandler):
    def get(self):
        articles = controller.get_articles(self, order='-views', limit=30)

        self.render('popular.html',
            articles=articles)

class LoginHandler(TemplatedRequestHandler):
    def get(self):
        if self.do_get_post():
            return

        self.render('login.html')

    def post(self):
        try:
            do_auth(self, controller.log_in)
        except RedirectionNeeded:
            return
        except (simpleeditions.LogInError,
                simpleeditions.NotConnectedError), e:
            self.add_error(str(e))
            self.render('login.html')
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
                self, req.get('title'), req.get('description'),
                req.get('content'), req.get('icon'))

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

class PublishArticleHandler(TemplatedRequestHandler):
    def post(self, article_id):
        article_id = int(article_id)
        controller.publish(self, article_id)
        self.redirect('/') # Redirect home, where the article will appear

class RegisterHandler(TemplatedRequestHandler):
    def get(self):
        # Make sure user isn't logged in
        user = self.user_obj
        if user:
            self.redirect('/')

        if self.do_get_post():
            return

        self.render('register.html', auth_type='local')

    def post(self):
        req = self.request
        auth_type = req.get('auth_type')
        auth_name = controller.get_auth_name(self, auth_type)

        try:
            if auth_type == 'local' or req.get('display_name'):
                do_auth(self, controller.register)
            else:
                # Get user data from external services so that it can be used
                # to pre-fill the registration form.
                display_name, email = do_auth(
                    self,
                    controller.get_auth_user_info)

                self.render('register.html',
                    auth_name=auth_name,
                    auth_type=auth_type,
                    auth_display_name=display_name,
                    auth_email=email)
                return
        except RedirectionNeeded:
            return
        except (simpleeditions.RegisterError,
                simpleeditions.ConnectError), e:
            self.add_error(str(e))

            self.render('register.html',
                auth_name=auth_name,
                auth_type=auth_type)

            return

        # User successfully logged in.
        self.redirect('/sign-up/success')

class RegisterSuccessHandler(TemplatedRequestHandler):
    def get(self):
        user = self.user_obj
        if user:
            self.render('register_success.html')
        else:
            self.redirect('/sign-up')
    post = get

class UserHandler(TemplatedRequestHandler):
    def get(self, user_id):
        try:
            user = None
            if user_id.isdigit():
                user_id = int(user_id)
                if self.user and self.user['id'] == user_id:
                    user = self.user
            elif self.user and self.user['canonical_name'] == user_id:
                user = self.user

            if not user:
                user = controller.get_user_info(self, user_id)

            articles = controller.get_articles_by_user(self, user['id'])
            self.render('user.html', user_info=user, user_articles=articles)
        except simpleeditions.NotFoundError:
            self.not_found()

_static_pages = ['about.html']
class StaticPageHandler(TemplatedRequestHandler):
    def get(self, page_slug):
        page = '%s.html' % page_slug
        if page in _static_pages:
            self.render(page)
        else:
            self.not_found()
