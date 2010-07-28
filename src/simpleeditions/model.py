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
import cgi
from datetime import datetime, timedelta
import hashlib
import os
import re
import time
import urllib
import uuid

from google.appengine.api import mail, urlfetch, users
from google.appengine.ext import db
from google.appengine.ext.db import polymodel
from google.appengine.runtime import apiproxy_errors

import facebook
import markdown2

import simpleeditions
from simpleeditions import settings, utils

def get_key(value, kind, parent=None):
    """Returns a key from value.

    """
    if issubclass(kind, db.Model):
        kind = kind.kind()
    elif not isinstance(kind, basestring):
        raise TypeError('Invalid type (kind); should be a Model subclass or a '
                        'string.')

    if isinstance(value, db.Key):
        assert value.kind() == kind, 'Tried to use a Key of the wrong kind.'
        assert value.parent() == parent, 'Invalid Key parent.'
        return value
    elif isinstance(value, db.Model):
        assert value.kind() == kind, 'Tried to use a Model of the wrong kind.'
        assert value.parent_key() == parent, 'Invalid Model parent.'
        return value.key()

    if isinstance(value, (basestring, int, long)):
        return db.Key.from_path(kind, value, parent=parent)
    else:
        raise TypeError('Invalid type (value); expected string, number, Key '
                        'or %s.' % kind)

def get_instance(value, model, parent=None):
    """Returns a model instance from value. If value is a string, gets by key
    name; if value is an integer, gets by id; if value is a key, gets by key
    and if value is an instance, returns the instance.

    """
    if not issubclass(model, db.Model):
        raise TypeError('Invalid type (model); expected subclass of Model.')

    if isinstance(value, basestring):
        return model.get_by_key_name(value, parent=parent)
    elif isinstance(value, (int, long)):
        return model.get_by_id(value, parent=parent)
    elif isinstance(value, db.Key):
        return db.get(value)
    elif isinstance(value, model):
        return value
    else:
        raise TypeError('Invalid type (value); expected string, number, Key '
                        'or %s.' % model.__name__)

def get_rpc():
    """Returns an RPC object tuned for queries that don't have to be 100%
    accurate. Queries using this RPC object may return up to a couple of
    seconds out-of-date data.

    """
    return db.create_rpc(deadline=5, read_policy=db.EVENTUAL_CONSISTENCY)

class User(db.Model):
    display_name = db.StringProperty(required=True)
    canonical_name = db.StringProperty(required=True)
    email = db.EmailProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    status = db.StringProperty(choices=('inactive', 'member', 'contributor',
                                        'staff', 'admin'),
                               default='member')
    session = db.StringProperty()
    expires = db.DateTimeProperty()

    # Actions that require permissions paired with functions that return True
    # if the supplied user has the permission.
    actions = {
        'comment':
            lambda user: True,
        'create-article':
            lambda user: user.status in ('contributor', 'staff', 'admin'),
        'edit-any-article':
            lambda user: user.status in ('staff', 'admin'),
        'upload-files':
            lambda user: user.status in ('contributor', 'staff', 'admin'),
    }

    @staticmethod
    def get_canonical_name(display_name):
        """Returns a version of the display name that can be used for case-
        and space-insensitive comparisons.

        """
        return display_name.lower().replace(' ', '')

    @staticmethod
    def get_session(session_id):
        """Retrieves a User instance for the currently logged in user.

        """
        # User has a session.
        query = User.all()
        query.filter('session =', session_id)
        query.filter('expires >', datetime.now())
        return query.get()

    @staticmethod
    def create(display_name, email=None):
        user = User(
            display_name=display_name,
            canonical_name=User.get_canonical_name(display_name))
        if email:
            user.email = email
        user.put()
        return user

    @staticmethod
    def validate(display_name, email=None):
        if len(display_name) < 2:
            raise simpleeditions.RegisterError(
                'Display name must be at least 2 characters long.')

        if len(display_name) > 25:
            raise simpleeditions.RegisterError(
                'Display name may not be any longer than 25 characters.')

        if not re.match('[a-zA-Z0-9 ]+$', display_name):
            raise simpleeditions.RegisterError(
                'The display name can only contain letters, numbers and '
                'spaces.')

        qry = User.all(keys_only=True).filter('display_name',
            User.get_canonical_name(display_name))
        if qry.get():
            raise simpleeditions.RegisterError(
                'That display name, or a very similar one, already exists.')

        if email:
            qry = User.all(keys_only=True).filter('email', email)
            if qry.get():
                raise simpleeditions.RegisterError('E-mail is already in use.')

            if not mail.is_email_valid(email):
                raise ValueError('A valid e-mail address must be provided.')

    def can(self, action):
        """Returns True if the user has permission to do the specified action.

        """
        try:
            return self.actions[action](self)
        except KeyError:
            raise ValueError('Unknown action %s.' % action)

    def end_session(self):
        """Removes a session from the database, effectively logging the user
        out.

        """
        self.session = None
        self.expires = None
        self.put()

    def start_session(self):
        """Gives the user a session id and stores it as a cookie in the user's
        browser.

        """
        # Create a unique session id.
        self.session = uuid.uuid4().get_hex()
        # Calculate the date/time for when the session will expire.
        self.expires = datetime.now() + timedelta(days=settings.SESSION_TTL)
        self.put()


class UserAuthType(polymodel.PolyModel):
    """Represents a method to authenticate to the application.

    """
    name = 'Unknown'

    @staticmethod
    def _register(auth_class, handler, display_name, email=None, *args,
                  **kwargs):
        user = User.create(display_name, email)
        auth = auth_class.add_to_user(handler, user, *args, **kwargs)
        return auth

    @classmethod
    def connect(cls, handler, user, *args, **kwargs):
        """Connects an authentication type to a user.

        """
        user = get_instance(user, User)
        if not user:
            raise ValueError('Did not get a valid user.')

        cls.validate(handler, *args, **kwargs)
        return cls.add_to_user(handler, user, *args, **kwargs)

    @staticmethod
    def get_user_info(handler, *args, **kwargs):
        """Returns a tuple of display name and e-mail available from the
        authentication service. If either is unavailable, an empty string is
        used instead.

        """
        return ('', '')

    @classmethod
    def register(cls, handler, display_name, email=None, *args, **kwargs):
        """Attempts to register a new user and connect it with this
        authentication type. The code is run in a transaction, so the user will
        not be created if connecting fails.

        """
        if not isinstance(display_name, basestring):
            raise TypeError('Display name must be a string.')

        if email:
            if not isinstance(email, basestring):
                raise TypeError('E-mail must be a string.')

            # Normalize e-mail address.
            email = email.strip().lower()

        # Clean display name.
        display_name = re.sub(' {2,}', ' ', display_name.strip())

        User.validate(display_name, email)
        cls.validate(handler, *args, **kwargs)
        return db.run_in_transaction(UserAuthType._register,
            cls, handler, display_name, email, *args, **kwargs)

    @staticmethod
    def validate(handler, *args, **kwargs):
        """Function for validating the parameters passed to the authentication
        class. If validation fails, an error should be raised.

        This is just an empty definition; implementation is left to sub-
        classes.

        """

class FacebookAuth(UserAuthType):
    """Supports authenticating to the application using Facebook.

    """
    name = 'Facebook'

    facebook_uid = db.IntegerProperty(required=True)

    @staticmethod
    def _add_user_data(handler, data):
        graph = facebook.GraphAPI(data['access_token'])
        user = graph.get_object('me')
        data['uid'] = user['id']
        data['name'] = user['name']
        if 'email' in user:
            data['email'] = user['email']

        # This cookie uses the same structure as the one created by the
        # Facebook JavaScript library.
        exp = datetime.now() + timedelta(seconds=int(data['expires']))
        data['expires'] = int(time.mktime(exp.timetuple()))
        payload = ''.join('%s=%s' % (k, data[k]) for k in
                          sorted(data.keys()))
        sig = hashlib.md5(payload + settings.FACEBOOK_SECRET)
        data['sig'] = sig.hexdigest()
        utils.set_cookie(handler,
            'fbs_%s' % settings.FACEBOOK_APP_ID,
            '"%s"' % urllib.urlencode(data),
            exp)

    @staticmethod
    def add_to_user(handler, user):
        data = FacebookAuth.get_data(handler)

        auth = FacebookAuth(
            parent=user,
            facebook_uid=int(data['uid']))
        auth.put()

        return auth

    @staticmethod
    def get_data(handler, extra_data=False):
        data = facebook.get_user_from_cookie(
            handler.request.cookies,
            str(settings.FACEBOOK_APP_ID),
            settings.FACEBOOK_SECRET)

        if not data:
            # No Facebook cookie available; check if we're in the process of
            # authing.
            code = handler.request.get('code')
            if code:
                # Since the redirect_uri is arbitrary, the current URL is used,
                # without the code parameter. This should always be the same as
                # the redirect_uri used for the previous request.
                redirect_uri = re.sub('&code=[^&]+', '', handler.request.url)

                result = urlfetch.fetch(
                    'https://graph.facebook.com/oauth/access_token'
                    '?client_id=%s&redirect_uri=%s&client_secret=%s'
                    '&code=%s&scope=email' % (
                        settings.FACEBOOK_APP_ID,
                        urllib.quote_plus(redirect_uri),
                        settings.FACEBOOK_SECRET,
                        urllib.quote_plus(code)))
                # Get a dict of the data returned by Facebook. It will look
                # like the following example:
                # {'access_token': '...', 'expires': '5860'}
                data = dict((k, v[-1]) for k, v in
                            cgi.parse_qs(result.content).items())
                # Get the UID of the current Facebook user.
                FacebookAuth._add_user_data(handler, data)
            else:
                raise simpleeditions.ExternalLoginNeededError(
                    'You must log in with Facebook first.')
        elif extra_data and ('name' not in data):
            FacebookAuth._add_user_data(handler, data)

        return data

    @staticmethod
    def get_login_url(return_path='/'):
        return_url = urllib.quote_plus('http://%s%s' % (
            settings.DOMAIN, return_path))
        return ('https://graph.facebook.com/oauth/authorize?client_id=%s'
                '&redirect_uri=%s' % (settings.FACEBOOK_APP_ID, return_url))

    @staticmethod
    def get_user_info(handler):
        data = FacebookAuth.get_data(handler, True)
        return (data['name'], data['email'] if 'email' in data else '')

    @staticmethod
    def log_in(handler):
        data = FacebookAuth.get_data(handler)
        uid = int(data['uid'])

        auth = FacebookAuth.gql('WHERE facebook_uid = :1', uid).get()
        if not auth:
            raise simpleeditions.NotConnectedError(
                'Facebook user %d is not connected to this application.' % uid)

        # No error so far means the user has been successfully authenticated.
        return auth

    @staticmethod
    def validate(handler):
        data = FacebookAuth.get_data(handler)
        uid = int(data['uid'])

        qry = FacebookAuth.all(keys_only=True).filter('facebook_uid', uid)
        if qry.get():
            raise simpleeditions.ConnectError('Facebook user is already in use.')

class LocalAuth(UserAuthType):
    """Supports authenticating to the application using the application
    datastore only.

    """
    name = 'SimpleEditions'

    password = db.ByteStringProperty(required=True, indexed=False)

    @staticmethod
    def add_to_user(handler, user, password):
        if not user.email:
            raise simpleeditions.ConnectError(
                'You must enter an e-mail when using password authentication.')

        password = password.encode('utf-8')
        salt = os.urandom(4)

        auth = LocalAuth(
            parent=user,
            password=salt + hashlib.sha256(password + salt).digest())
        auth.put()

        return auth

    @staticmethod
    def log_in(handler, email, password):
        """Retrieves a LocalAuth instance, based on an e-mail and a password.

        The SHA-256 hash of the password must match the hash stored in the
        datastore, otherwise an exception will be raised.

        """
        email = email.strip().lower()
        user = User.all(keys_only=True).filter('email', email).get()
        if user:
            auth = LocalAuth.all().ancestor(user).get()
            if auth:
                password = password.encode('utf-8')
                salt = auth.password[:4]
                hash = auth.password[4:]
                if hashlib.sha256(password + salt).digest() == hash:
                    return auth
        raise simpleeditions.LogInError(
            'Wrong e-mail address or password.')

    @staticmethod
    def validate(handler, password):
        if not isinstance(password, basestring):
            raise TypeError('The password must be supplied as a string.')

        if len(password) < 6:
            raise simpleeditions.ConnectError(
                'Password must be at least 6 characters long.')

class GoogleAuth(UserAuthType):
    """Supports authenticating to the application using Google's own
    authentication system for App Engine.

    """
    name = 'Google'

    google_user = db.UserProperty(required=True)

    @staticmethod
    def add_to_user(handler, user):
        google_user = users.get_current_user()

        auth = GoogleAuth(
            parent=user,
            google_user=google_user)
        auth.put()

        if not user.email:
            user.email = google_user.email()
            user.put()

        return auth

    @staticmethod
    def get_login_url(return_path='/'):
        return users.create_login_url(return_path)

    @staticmethod
    def get_user_info(handler):
        google_user = users.get_current_user()
        if not google_user:
            raise simpleeditions.ExternalLoginNeededError(
                'You must log in with Google first.')
        return (google_user.nickname(), google_user.email())

    @staticmethod
    def log_in(handler):
        """Retrieves the User instance connected to the currently logged in
        Google user.

        """
        google_user = users.get_current_user()
        if not google_user:
            raise simpleeditions.ExternalLoginNeededError(
                'You must log in with Google first.')

        auth = GoogleAuth.gql('WHERE google_user = :1', google_user).get()
        if not auth:
            raise simpleeditions.NotConnectedError(
                'Google user %s is not connected to this application. '
                'You need to register.' % google_user.nickname())

        # No error so far means the user has been successfully authenticated.
        return auth

    @staticmethod
    def validate(handler):
        google_user = users.get_current_user()
        if not google_user:
            raise simpleeditions.ExternalLoginNeededError(
                'You must log in with Google first.')
        qry = GoogleAuth.all(keys_only=True).filter('google_user', google_user)
        if qry.get():
            raise simpleeditions.ConnectError(
                'Google user %s is already in use.' % google_user.nickname())

AUTH_TYPES = dict(
    local=LocalAuth,
    facebook=FacebookAuth,
    google=GoogleAuth,
)

class Blob(db.Model):
    """Represents a user-submitted binary object. For example, an image.

    """
    owner = db.ReferenceProperty()
    user = db.ReferenceProperty(User, collection_name='blobs', required=True)
    user_name = db.StringProperty(required=True, indexed=False)
    created = db.DateTimeProperty(auto_now_add=True)
    data = db.BlobProperty(required=True)
    content_type = db.StringProperty(required=True, indexed=False)
    size = db.IntegerProperty(required=True)
    name = db.StringProperty(indexed=False)

    @classmethod
    def create(cls, owner, user, data, content_type, name=''):
        blob = cls.prepare(user, data, content_type, name)
        blob.owner = owner

        try:
            blob.put()
        except apiproxy_errors.RequestTooLargeError:
            raise simpleeditions.SaveBlobError(
                'The provided file was too large.')

        return blob

    @classmethod
    def prepare(cls, user, data, content_type, name=''):
        """Creates a new Blob. This does NOT put the Blob to the datastore,
        since the caller may want to use its key and then update it before
        storing it.

        """
        user = get_instance(user, User)
        if not user:
            raise ValueError('Did not get a valid user.')

        size = len(data)

        blob = cls(key_name=uuid.uuid4().get_hex(), user=user,
                   user_name=user.display_name, data=data,
                   content_type=content_type, size=size, name=name)
        return blob

    def data_as_base64(self):
        return base64.b64encode(self.data)


# Method for validating article slugs.
_validate_slug_re = None
def _validate_slug(slug):
    global _validate_slug_re
    if not _validate_slug_re:
        _validate_slug_re = re.compile('[a-z0-9]+(?:-[a-z0-9]+)*$')

    if not _validate_slug_re.match(slug):
        raise ValueError('The slug property must only consist of lower case '
                         'letters and numbers, optionally separated by '
                         'hyphens.')

class Article(db.Model):
    user = db.ReferenceProperty(User, collection_name='articles',
                                required=True)
    user_name = db.StringProperty(required=True, indexed=False)
    icon = db.ReferenceProperty(Blob)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now_add=True)
    last_save = db.DateTimeProperty(auto_now=True)
    comments = db.IntegerProperty(default=0)
    edits = db.IntegerProperty(default=0)
    views = db.IntegerProperty(default=0)
    slug = db.StringProperty(required=True, validator=_validate_slug)
    title = db.StringProperty(required=True)
    description = db.StringProperty(required=True, multiline=True,
                                    indexed=False)
    content = db.TextProperty(required=True)
    html = db.TextProperty(required=True)

    @staticmethod
    def _save(user, title=None, description=None, content=None, icon=None,
              message='', article=None):
        """Updates an article with the specified values. If no article is
        supplied, a new article will be created. This method should ALWAYS
        run in a transaction to ensure data consistency.

        """
        user = get_instance(user, User)
        if not user:
            raise ValueError('A valid user must be provided.')

        if icon:
            icon = get_key(icon, Blob)

        if not isinstance(message, basestring):
            raise TypeError('Message must be a string.')

        if article:
            article = get_instance(article, Article)
            if not article:
                raise ValueError('A valid article must be provided when '
                                 'updating.')

            # If the values do not change, behave as if no value was supplied
            # at all.
            if title == article.title:
                title = None
            if description == article.description:
                description = None
            if content == article.content:
                content = None
            if icon == article._entity['icon']:
                icon = None

            if not (title or description or content or icon):
                raise simpleeditions.SaveArticleError('Nothing to update.')

            # Only staff and the owner of the article may update it.
            if (article._entity['user'] != user.key() and
                not user.can('edit-any-article')):
                raise simpleeditions.SaveArticleError(
                    'You do not have the permissions to update that article.')
        elif not user.can('create-article'):
            raise simpleeditions.SaveArticleError(
                'You do not have the permissions to create an article.')

        if title:
            if not isinstance(title, basestring):
                raise TypeError('A valid title must be provided.')
            if len(title) > 50:
                raise simpleeditions.SaveArticleError(
                    'The title of an article may not be longer than 50 '
                    'characters.')
            slug = title.lower().replace('\'', '')
            slug = re.sub('[^a-z0-9]+', '-', slug).strip('-')
        else:
            slug = None

        if description:
            if not isinstance(description, basestring):
                raise TypeError('A valid description must be provided.')
            if len(description) > 500:
                raise simpleeditions.SaveArticleError(
                    'The description of an article may not be longer than 500 '
                    'characters.')

        if content:
            if not isinstance(content, basestring):
                raise TypeError('A valid article body must be provided.')
            html = markdown2.markdown(content)
        else:
            html = None

        if article:
            # Update already existing article.
            if title:
                article.title = title
                article.slug = slug
            if description:
                article.description = description
            if content:
                article.content = content
                article.html = html
            if icon:
                article.icon = icon
            article.edits += 1
            article.last_modified = datetime.now()
        else:
            try:
                article = Article(user=user, user_name=user.display_name,
                                  icon=icon, slug=slug, title=title,
                                  description=description, content=content,
                                  html=html)
            except db.BadValueError, e:
                raise simpleeditions.SaveArticleError(
                    'All required fields must be filled (%s).' % e)
        article.put()

        # Create a revision for the current article.

        # Get the next revision number. This is a number that starts at 1 for
        # the first revision, and then increments for every new revision. Since
        # revisions will never be deleted, it is safe to consider the revision
        # number as being the same as the number of edits made to the article,
        # plus one.
        number = article.edits + 1
        if number > 1:
            # There is an earlier revision that needs to be referenced and
            # updated. Get it.
            key = ArticleRevision.build_key(article, str(number - 1))
            previous = db.get(key)
        else:
            previous = None

        if len(message) > 500:
            raise simpleeditions.SaveArticleError(
                'The edit message cannot be any longer than 500 characters.')

        # The revision number is used as the key for the revision. This allows
        # well-performing queries for specific revisions.
        revision = ArticleRevision(
            key_name=str(number), parent=article, previous=previous, user=user,
            user_name=user.display_name, icon=article._entity['icon'],
            title=article.title, description=article.description,
            content=article.content, html=article.html, message=message)
        revision.put()

        if previous:
            # Give the previous revision a reference to the new revision.
            previous.next = revision
            previous.put()

        return article

    @staticmethod
    def _save_comment(article_key, user, content):
        article = Article.get(article_key)

        if not isinstance(user, User):
            raise TypeError('Invalid user.')

        if not isinstance(content, basestring):
            raise TypeError('Invalid content.')

        if len(content) < 10:
            raise simpleeditions.SaveCommentError(
                'A comment must be at least 10 characters long.')
        if len(content) > 500:
            raise simpleeditions.SaveCommentError(
                'Comments may not be any longer than 500 characters.')

        article.comments += 1

        comment = ArticleComment(
            parent=article_key, user=user, user_name=user.display_name,
            content=content)

        try:
            comment.put()
            article.put()
        except apiproxy_errors.CapabilityDisabledError:
            raise simpleeditions.SaveCommentError(
                'Sorry, the database is currently in maintenance. Try again '
                'later.')

        return comment

    @staticmethod
    def add_comment(article, user, content):
        return db.run_in_transaction(Article._save_comment,
            get_key(article, Article), get_instance(user, User), content)

    @staticmethod
    def create(user, title, description, content, icon=None):
        return db.run_in_transaction(Article._save,
            user, title, description, content, icon)

    @staticmethod
    def update(article, user, title=None, description=None, content=None,
               icon=None, message=''):
        """Updates the article. An empty/false value for title or content means
        that it should not be changed.

        """
        return db.run_in_transaction(Article._save,
            user, title, description, content, icon, message, article=article)

class ArticleComment(db.Model):
    user = db.ReferenceProperty(User, collection_name='comments',
                                required=True)
    user_name = db.StringProperty(required=True, indexed=False)
    created = db.DateTimeProperty(auto_now_add=True)
    content = db.StringProperty(required=True, multiline=True, indexed=False)

    @classmethod
    def all_for_article(cls, article):
        """Returns a Query instance that will only return comment instances
        that are bound to the specificed article id/key/instance.

        """
        article = get_key(article, Article)
        return cls.all().ancestor(article)

class ArticleRevision(db.Model):
    previous = db.SelfReferenceProperty(indexed=False, collection_name='_1')
    next = db.SelfReferenceProperty(indexed=False, collection_name='_2')
    user = db.ReferenceProperty(User, collection_name='revisions',
                                required=True)
    user_name = db.StringProperty(required=True, indexed=False)
    icon = db.ReferenceProperty(Blob)
    created = db.DateTimeProperty(auto_now_add=True)
    title = db.StringProperty(required=True, indexed=False)
    description = db.StringProperty(required=True, multiline=True,
                                    indexed=False)
    content = db.TextProperty(required=True)
    html = db.TextProperty(required=True)
    message = db.StringProperty(indexed=False)

    @classmethod
    def all_for_article(cls, article):
        """Returns a Query instance that will only return revision instances
        that are bound to the specificed article id/key/instance.

        """
        article = get_key(article, Article)
        return cls.all().ancestor(article)

    @classmethod
    def build_key(cls, article, revision):
        """Returns a key referencing a specific revision instance given an
        article id/key/instance and a revision number.

        """
        article = get_key(article, Article)
        # Build a key that references the requested revision for the specified
        # article.
        return db.Key.from_path(cls.kind(), str(revision), parent=article)
