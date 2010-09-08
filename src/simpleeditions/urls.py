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
    (r'/popular', view.PopularHandler),
    (r'/recent', view.RecentHandler),
    (r'/(about)', view.StaticPageHandler),

    # List of articles
    (r'/articles', view.ArticlesHandler),

    # Pages for an article
    (r'/(\d+)(?:/[a-z0-9-]+)?', view.ArticleHandler),
    (r'/(\d+)/manage/edit', view.EditArticleHandler),
    (r'/(\d+)/manage/files/', view.ArticleFilesHandler),
    (r'/(\d+)/manage/publish', view.PublishArticleHandler),
    (r'/(\d+)/manage/revisions/', view.ArticleRevisionsHandler),
    (r'/(\d+)/manage/revisions/(\d+)', view.ArticleRevisionHandler),
    (r'/new', view.NewArticleHandler),

    # Account control
    (r'/sign-up', view.RegisterHandler),
    (r'/sign-up/success', view.RegisterSuccessHandler),
    (r'/login', view.LoginHandler),
    (r'/logout', view.LogOutHandler),
    (r'/user/([a-z][a-z\d]*)', view.UserHandler),
    (r'/user/(\d+)', view.UserHandler),

    # Uploaded files handler
    (r'/content/([a-f0-9]{32})(?:\.[a-z0-9]+)?', view.BlobHandler),

    # API handler
    (r'/api/(\w+)', view.ApiHandler),

    # All other paths go to the 404 page
    (r'.*', view.NotFoundHandler),
)
