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
import hashlib
import re
import uuid

from google.appengine.api import mail, users
from google.appengine.ext import db
from google.appengine.ext.db import polymodel

import markdown2

import simpleeditions
from simpleeditions import settings

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


class User(db.Model):
    display_name = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    status = db.StringProperty(choices=('inactive', 'member', 'admin'),
                               default='member')
    session = db.StringProperty()
    expires = db.DateTimeProperty()

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
    def register(display_name, email=None):
        user = User(display_name=display_name)
        if email:
            user.email = email
        user.put()
        return user

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
    user = db.ReferenceProperty(User, collection_name='auth_types',
                                required=True)

    @staticmethod
    def _register(auth_class, display_name, email=None, *args, **kwargs):
        user = User.register(display_name, email)
        auth = auth_class.add_to_user(user, *args, **kwargs)
        return auth

    @classmethod
    def connect(cls, user, *args, **kwargs):
        """Connects an authentication type to a user.

        """
        user = get_instance(user, User)
        if not user:
            raise ValueError('Did not get a valid user.')

        cls.validate(*args, **kwargs)
        return cls.add_to_user(user, *args, **kwargs)

    @classmethod
    def register(cls, display_name, email=None, *args, **kwargs):
        """Attempts to register a new user and connect it with this
        authentication type. The code is run in a transaction, so the user will
        not be created if connecting fails.

        """
        cls.validate(*args, **kwargs)
        return db.run_in_transaction(UserAuthType._register,
            cls, display_name, email, *args, **kwargs)

    @staticmethod
    def validate(*args, **kwargs):
        """Function for validating the parameters passed to the authentication
        class. If validation fails, an error should be raised.

        This is just an empty definition; implementation is left to sub-
        classes.

        """

class LocalAuth(UserAuthType):
    """Supports authenticating to the application using the application
    datastore only.

    """
    email = db.EmailProperty(required=True)
    password = db.StringProperty(required=True, indexed=False)

    @staticmethod
    def add_to_user(user, auth_email, password):
        auth = LocalAuth(
            parent=user,
            user=user,
            email=auth_email.strip().lower(),
            password=hashlib.sha256(password).hexdigest())
        auth.put()
        return auth

    @staticmethod
    def log_in(auth_email, password):
        """Retrieves a LocalAuth instance, based on an e-mail and a password.

        The SHA-256 hash of the password must match the hash stored in the
        datastore, otherwise an exception will be raised.

        """
        email = auth_email.strip().lower()
        auth = LocalAuth.gql('WHERE email = :1', email).get()
        if not auth or hashlib.sha256(password).hexdigest() != auth.password:
            raise simpleeditions.LogInError(
                'Wrong e-mail address or password.')

        # No error so far means the user has been successfully authenticated.
        return auth

    @staticmethod
    def validate(auth_email, password):
        if not isinstance(auth_email, basestring):
            raise TypeError('The e-mail address must be supplied as a string.')
        if not isinstance(password, basestring):
            raise TypeError('The password must be supplied as a string.')

        email = auth_email.strip().lower()

        qry = LocalAuth.all(keys_only=True).filter('email', email)
        if qry.get():
            raise simpleeditions.ConnectError('E-mail is already in use.')

        if not mail.is_email_valid(email):
            raise ValueError('A valid e-mail address must be provided.')

        if len(password) < 4:
            raise ValueError('Password must be at least 4 characters long.')

class GoogleAuth(UserAuthType):
    """Supports authenticating to the application using Google's own
    authentication system for App Engine.

    """
    google_user = db.UserProperty(required=True)

    @staticmethod
    def add_to_user(user):
        auth = GoogleAuth(
            parent=user,
            user=user,
            google_user=users.get_current_user())
        auth.put()
        return auth

    @staticmethod
    def get_login_url(return_url='/'):
        return users.create_login_url(return_url)

    @staticmethod
    def log_in():
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
                'That Google user is not connected to this application.')

        # No error so far means the user has been successfully authenticated.
        return auth

    @staticmethod
    def validate():
        google_user = users.get_current_user()
        if not google_user:
            raise simpleeditions.ExternalLoginNeededError(
                'You must log in with Google first.')
        qry = GoogleAuth.all(keys_only=True).filter('google_user', google_user)
        if qry.get():
            raise simpleeditions.ConnectError('Google user is already in use.')

AUTH_TYPES = dict(
    local=LocalAuth,
    google=GoogleAuth,
)

class Blob(db.Model):
    """Represents a user-submitted binary object. For example, an image.

    """
    user = db.ReferenceProperty(User, collection_name='blobs', required=True)
    user_name = db.StringProperty(required=True, indexed=False)
    created = db.DateTimeProperty(auto_now_add=True)
    data = db.BlobProperty(required=True)
    content_type = db.StringProperty(required=True, indexed=False)
    size = db.IntegerProperty(required=True)
    description = db.StringProperty(indexed=False)

    @classmethod
    def create(cls, user, data, content_type, description=''):
        user = get_instance(user, User)
        if not user:
            raise ValueError('Did not get a valid user.')

        size = len(data)

        blob = cls(key_name=uuid.uuid4().get_hex(), user=user,
                   user_name=user.display_name, data=data,
                   content_type=content_type, size=size)
        blob.put()
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
    edits = db.IntegerProperty(default=0)
    views = db.IntegerProperty(default=0)
    slug = db.StringProperty(required=True, validator=_validate_slug)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    html = db.TextProperty(required=True)

    @staticmethod
    def _save(user, title=None, content=None, icon=None, message='',
              article=None):
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
            if content == article.content:
                content = None
            if icon == article._entity['icon']:
                icon = None

            if not title and not content and not icon:
                raise simpleeditions.SaveArticleError('Nothing to update.')

            # Right now, only the owner of the article may update it.
            if article._entity['user'] != user.key():
                raise simpleeditions.SaveArticleError(
                    'You do not have the permissions to update that article.')

        if title:
            if not isinstance(title, basestring):
                raise TypeError('A valid title must be provided.')

            slug = title.lower().replace('\'', '')
            slug = re.sub('[^a-z0-9]+', '-', slug).strip('-')
        elif not article:
            raise simpleeditions.SaveArticleError('A title is required.')
        else:
            slug = None

        if content:
            if not isinstance(content, basestring):
                raise TypeError('A valid article body must be provided.')

            html = markdown2.markdown(content)
        elif not article:
            raise simpleeditions.SaveArticleError('Content is required.')
        else:
            html = None

        if article:
            # Update already existing article.
            if title:
                article.title = title
                article.slug = slug
            if content:
                article.content = content
                article.html = html
            if icon:
                article.icon = icon
            article.edits += 1
            article.last_modified = datetime.now()
        else:
            article = Article(user=user, user_name=user.display_name,
                              icon=icon, slug=slug, title=title,
                              content=content, html=html)
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

        # The revision number is used as the key for the revision. This allows
        # well-performing queries for specific revisions.
        revision = ArticleRevision(
            key_name=str(number), parent=article, previous=previous, user=user,
            user_name=user.display_name, icon=article._entity['icon'],
            title=article.title, content=article.content, html=article.html,
            message=message)
        revision.put()

        if previous:
            # Give the previous revision a reference to the new revision.
            previous.next = revision
            previous.put()

        return article

    @staticmethod
    def create(user, title, content, icon=None):
        return db.run_in_transaction(Article._save, user, title, content, icon)

    @staticmethod
    def update(article, user, title=None, content=None, icon=None, message=''):
        """Updates the article. An empty/false value for title or content means
        that it should not be changed.

        """
        return db.run_in_transaction(Article._save, user, title, content, icon,
                                     message, article=article)

class ArticleRevision(db.Model):
    previous = db.SelfReferenceProperty(indexed=False, collection_name='_1')
    next = db.SelfReferenceProperty(indexed=False, collection_name='_2')
    user = db.ReferenceProperty(User, collection_name='revisions',
                                required=True)
    user_name = db.StringProperty(required=True, indexed=False)
    icon = db.ReferenceProperty(Blob)
    created = db.DateTimeProperty(auto_now_add=True)
    title = db.StringProperty(required=True, indexed=False)
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
