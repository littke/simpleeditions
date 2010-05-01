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

import os
import os.path

from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

from simpleeditions import settings

class TemplatedRequestHandler(webapp.RequestHandler):
    """Simplifies handling requests. In particular, it simplifies working
    with templates, with its render() method.

    """

    def redirect(self, location, permanent=False):
        res = self.response

        res.clear()
        res.headers['Location'] = location
        res.set_status(301 if permanent else 302)

    def render(self, template_name, values=None, **kwargs):
        """Renders the specified template to the output.

        The template will have the following variables available, in addition
        to the ones specified in the render() method:
        - DEBUG: Whether the application is running in debug mode.
        - STATIC_PATH: The path under which all static content lies.
        - VERSION: The version of the application.
        - request: The current request object. Has attributes such as 'path',
                   'query_string', etc.

        """

        if values is not None and not isinstance(values, dict):
            raise TypeError('values must be None or of type dict')

        kwargs.update({'DEBUG': settings.DEBUG,
                       'STATIC_PATH': settings.STATIC_PATH,
                       'VERSION': os.environ['CURRENT_VERSION_ID'],
                       'request': self.request})
        if values:
            kwargs.update(values)

        path = os.path.join(settings.TEMPLATE_DIR, template_name)
        self.response.out.write(template.render(path, kwargs))

def public(func):
    """A decorator that defines a function as publicly accessible.

    """
    func.__public = True
    return func
