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
import logging
import os
import os.path
import sys
import time
import traceback

from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

from simpleeditions import settings

class TemplatedRequestHandler(webapp.RequestHandler):
    """Simplifies handling requests. In particular, it simplifies working
    with templates, with its render() method.

    """

    def __init__(self):
        self._errors = []

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

    def add_error(self, message):
        """Adds an error message. All errors will be available as the template
        variable "errors".

        """
        self._errors.append(message)

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
                       'STATIC_PATH': settings.STATIC_PATH,
                       'VERSION': settings.VERSION,
                       'errors': self._errors,
                       'request': self.request})

        path = os.path.join(settings.TEMPLATE_DIR, template_name)
        self.response.out.write(template.render(path, kwargs))

def _get_value(obj, name):
    """Gets a value from an object. First tries to get the attribute with the
    specified name. If that fails, it tries to use the object as a dict
    instead. If the value is callable, the return value of the callable is
    used.

    """
    try:
        value = getattr(obj, name)
    except AttributeError:
        try:
            # If the attribute doesn't exist, attempt to use the object as a dict.
            value = obj[name]
        except:
            # Failing that, just return None.
            return None
    # If the value is callable, call it and use its return value.
    return value() if callable(value) else value

def get_dict(obj, attributes):
    """Returns a dict with keys/values of a list of attributes from an object.

    """
    result = dict()
    for attr in attributes:
        if isinstance(attr, basestring):
            alias = None
        else:
            # If a value in the attributes list is not a string, it should be
            # two packed values: the attribute name and the key name it should
            # have in the dict.
            attr, alias = attr

        # Since the obj variable is needed for future iterations, its value is
        # stored in a new variable that can be manipulated.
        value = obj

        if '.' in attr:
            # Dots in the attribute name can be used to fetch values deeper
            # into the object structure.
            for sub_attr in attr.split('.'):
                value = _get_value(value, sub_attr)
            if not alias:
                alias = sub_attr
        else:
            value = _get_value(value, attr)

        # Store the value in the dict.
        result[alias if alias else attr] = value

    return result

def public(func):
    """A decorator that defines a function as publicly accessible.

    """
    func.__public = True
    return func

def set_cookie(handler, name, value, expires=None, path='/'):
    # Build cookie data.
    if expires:
        ts = time.strftime('%a, %d-%b-%Y %H:%M:%S GMT', expires.timetuple())
        cookie = '%s=%s; expires=%s; path=%s' % (name, value, ts, path)
    else:
        cookie = '%s=%s; path=%s' % (name, value, path)

    # Send cookie to browser.
    handler.response.headers['Set-Cookie'] = cookie
    handler.request.cookies[name] = value
