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

from simpleeditions import view

urlpatterns = (
    # Content pages
    (r'/', view.HomeHandler),
    (r'/(about)', view.StaticPageHandler),

    # List of articles
    (r'/tutorials', view.ArticlesHandler),

    # Pages for an article
    (r'/(\d+)(?:/.*)?', view.ArticleHandler),
    (r'/edit/(\d+)', view.EditArticleHandler),
    (r'/new', view.NewArticleHandler),
    (r'/revisions/(\d+)/', view.ArticleRevisionsHandler),
    (r'/revisions/(\d+)/(\d+)', view.ArticleRevisionHandler),

    # Account control
    (r'/login', view.LoginHandler),
    (r'/logout', view.LogOutHandler),
    (r'/(?:register|join)', view.RegisterHandler),

    # API handler
    (r'/api/(\w+)', view.ApiHandler),

    # All other paths go to the 404 page
    (r'.*', view.NotFoundHandler),
)
