#!/usr/bin/env python
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

"""Entry point for the SimpleEditions application.

"""

import logging
import os
import wsgiref.handlers

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

import simpleeditions.settings
import simpleeditions.urls

def main():
    application = webapp.WSGIApplication(
        simpleeditions.urls.urlpatterns,
        debug=simpleeditions.settings.DEBUG)

    # Run the WSGI CGI handler with the application.
    util.run_wsgi_app(application)

if __name__ == '__main__':
    main()
