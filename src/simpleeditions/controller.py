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

from datetime import datetime, timedelta
import os

from google.appengine.api import images, memcache
from google.appengine.runtime import apiproxy_errors

import simpleeditions
from simpleeditions import model, settings, utils
from simpleeditions.utils import public

def create_icon(user, icon_data):
    # Resize image to 50x52 and store the result as PNG.
    icon_data = images.resize(icon_data, 50, 52)
    return model.Blob.create(user, icon_data, 'image/png')

def get_article_dict(article, include_content=False):
    props = ['key.id', ('_entity.user.id', 'user_id'), 'user_name',
             ('_entity.icon.name', 'icon'), 'created', 'last_modified',
             'edits', 'views', 'slug', 'title', 'description']
    if include_content:
        props += ['content', 'html']
    return utils.get_dict(article, props)

def get_auth_class(auth_type):
    try:
        return model.AUTH_TYPES[auth_type]
    except KeyError:
        raise ValueError('Invalid authentication type.')

def get_blob(name, article=None):
    if article:
        article = model.get_key(article, model.Article)
    return model.Blob.get_by_key_name(name, parent=article)

def get_blob_dict(blob, include_data=False):
    props = ['key.name', ('_entity.user.id', 'user_id'), 'user_name',
             'created', 'content_type', 'size']
    if include_data:
        props += [('data_as_base64', 'data')]

def get_current_user(handler):
    try:
        session_id = handler.request.cookies['session']
        return model.User.get_session(session_id)
    except KeyError:
        return None

def get_revision_dict(revision, include_content=False):
    props = [('key.name', 'number'), ('parent_key.id', 'article_id'),
             ('_entity.previous.name', 'previous'),
             ('_entity.next.name', 'next'), ('_entity.user.id', 'user_id'),
             'user_name', ('_entity.icon.name', 'icon'), 'created', 'title',
             'description', 'message']
    if include_content:
        props += ['content', 'html']
    return utils.get_dict(revision, props)

def get_user_dict(user, include_private_values=False):
    props = ['key.id', 'display_name', 'created', 'status']
    if include_private_values:
        props += ['email']
    user_dict = utils.get_dict(user, props)

    for action in user.actions:
        user_dict['can_%s' % action.replace('-', '_')] = user.can(action)

    return user_dict

def start_user_session(handler, user):
    user.start_session()
    utils.set_cookie(handler, 'session', user.session, user.expires)

@public
def connect(handler, auth_type, **kwargs):
    """Adds an authentication method to the current user.

    """
    user = handler.user_obj
    if not user:
        raise simpleeditions.NotLoggedInError(
            'You must be logged in to be able to add an authentication method '
            'to your account.')

    auth_class = get_auth_class(auth_type)
    auth_class.connect(handler, user, **kwargs)

@public
def create_article(handler, title, description, content, icon_data=None):
    user = handler.user_obj
    if not user:
        raise simpleeditions.NotLoggedInError(
            'You must be logged in to create an article.')

    try:
        icon_blob = create_icon(user, icon_data) if icon_data else None
    except images.BadImageError:
        raise simpleeditions.SaveArticleError(
            'The supplied file could not be used as an icon. Try another '
            'image.')

    try:
        article = model.Article.create(user, title, description, content,
                                       icon_blob)
    except apiproxy_errors.CapabilityDisabledError:
        raise simpleeditions.SaveArticleError(
            'Sorry, the database is currently in maintenance. Try again '
            'later.')

    return get_article_dict(article)

@public
def get_article(handler, id, include_content=False, view=False):
    article = model.Article.get_by_id(id)
    if not article:
        raise simpleeditions.ArticleNotFoundError(
            'Could not find article with id %r.' % id)

    if view:
        view_article(handler, article)

    return get_article_dict(article, include_content)

@public
def get_articles(handler, order, limit, include_content=False):
    rpc = model.get_rpc()
    articles = model.Article.all().order(order).fetch(limit, rpc=rpc)
    return [get_article_dict(article, include_content) for article in articles]

@public
def get_auth_user_info(handler, auth_type, **kwargs):
    auth_class = get_auth_class(auth_type)
    return auth_class.get_user_info(handler, **kwargs)

@public
def get_auth_name(handler, auth_type):
    auth_class = get_auth_class(auth_type)
    return auth_class.name

@public
def get_login_url(handler, auth_type, return_url='/'):
    try:
        auth_class = model.AUTH_TYPES[auth_type]
    except KeyError:
        raise ValueError('Invalid authentication type.')

    return auth_class.get_login_url(return_url)

@public
def get_revision(handler, article_id, revision):
    if not isinstance(article_id, (int, long)):
        raise TypeError('Article id must be an integer')

    key = model.ArticleRevision.build_key(article_id, revision)
    revision = model.ArticleRevision.get(key)
    if not revision:
        raise simpleeditions.RevisionNotFoundError(
            'Could not find article, revision pair with ids %r, %r.' % (
                article_id, revision))
    return get_revision_dict(revision, True)

@public
def get_revisions(handler, article_id):
    if not isinstance(article_id, (int, long)):
        raise TypeError('Article id must be an integer')

    rpc = model.get_rpc()
    query = model.ArticleRevision.all_for_article(article_id)
    revisions = query.order('-created').fetch(10, rpc=rpc)
    return [get_revision_dict(revision) for revision in revisions]

@public
def get_user_info(handler, id=None):
    """Returns information about a user. The current user is returned if no id
    is specified.

    """
    if id:
        rpc = model.get_rpc()
        user = model.User.get_by_id(id, rpc=rpc)
        if not user:
            raise simpleeditions.UserNotFoundError(
                'Could not find user with id %r.' % id)
        return get_user_dict(user)
    else:
        # This behavior is slightly backwards, with the controller getting data
        # from a view-provided value, but it's necessary to avoid getting the
        # user more than once.
        return handler.user

@public
def log_in(handler, auth_type, **kwargs):
    auth_class = get_auth_class(auth_type)

    # Check whether user provided values that are not supported by the chosen
    # auth type.
    code = auth_class.log_in.func_code
    args = code.co_varnames[1:code.co_argcount]
    extra_args = set(kwargs) - set(args)
    if extra_args:
        raise simpleeditions.LogInError(
            'Got unexpected values: %s' % ', '.join(extra_args))

    try:
        auth = auth_class.log_in(handler, **kwargs)
    except TypeError:
        raise simpleeditions.LogInError(
            'Could not log in with the provided information. Make sure all '
            'values (%s) were supplied.' % ', '.join(args))

    user = auth.parent()

    # Start a session and create a session cookie.
    start_user_session(handler, user)

    return get_user_dict(user, True)

@public
def log_out(handler):
    user = handler.user_obj
    if user:
        user.end_session()

        # Empty session cookie and force it to expire.
        utils.set_cookie(handler, 'session', '', datetime(1987, 7, 31, 3, 42))

@public
def register(handler, auth_type, **kwargs):
    if handler.user_obj:
        raise simpleeditions.RegisterError(
            'You cannot register while logged in.')

    auth_class = get_auth_class(auth_type)

    # Check whether user provided values that are not supported by the chosen
    # auth type.
    code = auth_class.register.func_code
    args = code.co_varnames[2:code.co_argcount]
    extra_args = set(kwargs) - set(args)
    code = auth_class.add_to_user.func_code
    extra_args -= set(code.co_varnames[2:code.co_argcount])
    if extra_args:
        raise simpleeditions.RegisterError(
            'Got unexpected values: %s' % ', '.join(extra_args))

    try:
        auth = auth_class.register(handler, **kwargs)
    except TypeError:
        raise simpleeditions.RegisterError(
            'Could not register with the provided information. Make sure all '
            'values (%s) were supplied.' % ', '.join(args))

    user = auth.parent()
    start_user_session(handler, user)
    return get_user_dict(user, True)

@public
def update_article(handler, id, title=None, description=None, content=None,
                   icon_data=None, message=''):
    if not isinstance(id, int):
        raise TypeError('Article id must be an integer.')

    user = handler.user_obj
    if not user:
        raise simpleeditions.NotLoggedInError(
            'You must be logged in to update an article.')

    try:
        icon_blob = create_icon(user, icon_data) if icon_data else None
    except images.BadImageError:
        raise simpleeditions.SaveArticleError(
            'The supplied file could not be used as an icon. Try another '
            'image.')

    try:
        article = model.Article.update(id, user, title, description, content,
                                       icon_blob, message)
    except apiproxy_errors.CapabilityDisabledError:
        raise simpleeditions.SaveArticleError(
            'Sorry, the database is currently in maintenance. Try again '
            'later.')

    return get_article_dict(article)

@public
def view_article(handler, id):
    if isinstance(id, model.Article):
        article = id
        id = article.key().id()
    elif isinstance(id, (int, long)):
        article = None
    else:
        raise TypeError('Invalid article id.')

    # Don't count views from certain crawler bots to avoid upping the number of
    # views for non-human visits.
    for user_agent in settings.IGNORED_USER_AGENTS:
        if user_agent in os.environ['HTTP_USER_AGENT']:
            return

    # memcache key used for counting views.
    views_key = 'article:%d:views' % id
    cached_views = None

    # Don't increment views if user has article id in cookie.
    try:
        cookie = handler.request.cookies['articles']
    except KeyError:
        cookie = ':'
    if not (':%d:' % id) in cookie:
        cookie += ('%d:' % id)
        utils.set_cookie(handler, 'articles', cookie,
                         datetime.now() + timedelta(days=7))

        # Id was not in cookie, increment by one if IP has not incremented
        # 5 or more times before.
        ip_key = 'article:%d:views:%s' % (id, os.environ['REMOTE_ADDR'])
        if memcache.get(ip_key) < 5:
            memcache.incr(ip_key, initial_value=0)
            cached_views = memcache.incr(views_key, initial_value=0) or 0L

    if cached_views is None:
        cached_views = long(memcache.get(views_key) or 0L)

    if article:
        # Aggregate stored views with cached views.
        article.views += cached_views

        # Store views to entity once every 10 minutes and reset the cache
        # counter.
        try:
            if datetime.now() - article.last_save > timedelta(minutes=10):
                article.put()
                memcache.delete(views_key)
        # In maintenance periods, avoid throwing errors when viewing an
        # article.
        except apiproxy_errors.CapabilityDisabledError:
            pass
