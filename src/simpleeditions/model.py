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

from google.appengine.ext import db

class User(db.Model):
    display_name = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    password = db.StringProperty()
    account_type = db.StringProperty(
        default='local', choices=('local', 'facebook', 'google', 'openid'))

class Article(db.Model):
    user = db.ReferenceProperty(User, collection_name='articles',
                                required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    slug = db.StringProperty(required=True, validator=_validate_slug)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    html = db.TextProperty(required=True)

class ArticleRevision(db.Model):
    article = db.ReferenceProperty(Article, collection_name='revisions',
                                   required=True)
    user = db.ReferenceProperty(User, collection_name='revisions',
                                required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    diff = db.TextProperty(required=True)
    content = db.TextProperty(required=True)
    html = db.TextProperty(required=True)

_validate_slug_re = None
def _validate_slug(slug):
    global _validate_slug_re
    if not _validate_slug_re:
        import re
        _validate_slug_re = re.compile('[a-z0-9]+(?:-[a-z0-9]+)*$')

    if not _validate_slug_re.match(slug):
        raise ValueError('The slug property must only consist of lower case '
                         'letters and numbers, optionally separated by '
                         'hyphens.')
