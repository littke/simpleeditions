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

"""A set of functions that control the application.

The purpose of this module is to provide a bridge between the user (through
views) and the back-end (models and data logic).

"""

import simpleeditions
from simpleeditions import model, utils
from simpleeditions.utils import public

def _get_article_dict(article, include_content=False):
    if include_content:
        props = ['key.id', ('_entity.user.id', 'user_id'), 'created',
                 'last_modified', 'slug', 'title', 'content', 'html']
    else:
        props = ['key.id', ('_entity.user.id', 'user_id'), 'created',
                 'last_modified', 'slug', 'title']
    return utils.get_dict(article, props)

def _get_user_dict(user, include_private_values=False):
    if include_private_values:
        props = ['key.id', 'display_name', 'email', 'created', 'status']
    else:
        props = ['key.id', 'display_name', 'created', 'status']
    return utils.get_dict(user, props)

@public
def create_article(handler, title, content):
    user = model.User.get_current(handler)
    if not user:
        raise simpleeditions.NotLoggedInError(
            'You must be logged in to create an article.')
    article = model.Article.create(user, title, content)

    return _get_article_dict(article)

@public
def get_article(handler, id):
    article = model.Article.get_by_id(id)
    if not article:
        raise simpleeditions.ArticleNotFoundError(
            'Could not find article with id %r.' % id)

    return _get_article_dict(article, True)

@public
def get_login_url(handler, auth_type, return_url='/'):
    try:
        auth_class = model.AUTH_TYPES[auth_type]
    except KeyError:
        raise ValueError('Invalid authentication type.')

    return auth_class.get_login_url(return_url)

@public
def get_user_info(handler, id=None):
    """Returns information about a user. The current user is returned if no id
    is specified.

    """
    if id:
        user = model.User.get_by_id(id)
        if not user:
            raise simpleeditions.UserNotFoundError(
                'Could not find user with id %r.' % id)
        return _get_user_dict(user)
    else:
        user = model.User.get_current(handler)
        if user:
            return _get_user_dict(user, True)

@public
def log_in(handler, auth_type, *args, **kwargs):
    try:
        auth_class = model.AUTH_TYPES[auth_type]
    except KeyError:
        raise ValueError('Invalid authentication type.')

    auth = auth_class.log_in(*args, **kwargs)
    auth.user.start_session(handler)
    return _get_user_dict(auth.user, True)

@public
def log_out(handler):
    user = model.User.get_current(handler)
    if user:
        user.end_session(handler)

@public
def register(handler, auth_type, *args, **kwargs):
    try:
        auth_class = model.AUTH_TYPES[auth_type]
    except KeyError:
        raise ValueError('Invalid authentication type.')

    auth = auth_class.register(*args, **kwargs)
    auth.user.start_session(handler)
    return _get_user_dict(auth.user, True)

@public
def update_article(handler, id, title=None, content=None, message=''):
    if not isinstance(id, int):
        raise TypeError('Article id must be an integer.')

    user = model.User.get_current(handler)
    if not user:
        raise simpleeditions.NotLoggedInError(
            'You must be logged in to update an article.')

    article = model.Article.update(id, user, title, content, message)
    return _get_article_dict(article)
