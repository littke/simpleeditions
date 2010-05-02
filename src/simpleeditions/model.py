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

from datetime import datetime, timedelta
import hashlib
import re
import time
import uuid

from google.appengine.api import mail, users
from google.appengine.ext import db
from google.appengine.ext.db import polymodel

import markdown2

import simpleeditions
from simpleeditions import settings

class PublicUser(db.Model):
    display_name = db.StringProperty()
    created = db.DateTimeProperty()
    status = db.StringProperty()

    @classmethod
    def kind(cls):
        return 'User'

    def put(self):
        raise simpleeditions.ReadOnlyError(
            'Public user data cannot be modified.')

class User(db.Model):
    display_name = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    status = db.StringProperty(choices=('inactive', 'member', 'admin'),
                               default='member')
    session = db.StringProperty()
    expires = db.DateTimeProperty()

    @staticmethod
    def get_current(handler):
        """Retrieves a User instance for the currently logged in user.

        """
        try:
            # User has a session.
            session = handler.request.cookies['session']
            query = User.all()
            query.filter('session =', session)
            query.filter('expires >', datetime.utcnow())
            user = query.get()
        except KeyError:
            user = None

        return user

    @staticmethod
    def register(display_name, email=None):
        user = User(display_name=display_name)
        if email:
            user.email = email
        user.put()
        return user

    def as_public(self):
        """Returns a PublicUser version of this object.

        """
        props = self.properties()

        pu = PublicUser()
        for prop in pu.properties().values():
            # Only copy properties that exist for both the PublicUser model and
            # the User model.
            if prop.name in props:
                # This line of code sets the property of the PublicUser
                # instance to the value of the same property on the User
                # instance.
                prop.__set__(pu, props[prop.name].__get__(self, type(self)))

        return pu

    def end_session(self, handler):
        """Removes a session from the database and the client, effectively
        logging the user out.

        """
        self.session = None
        self.expires = None
        self.put()

        # Empty session cookie and force it to expire.
        cookie = 'session=; expires=Fri, 31-Jul-1987 03:42:33 GMT'
        handler.response.headers['Set-Cookie'] = cookie
        del handler.request.cookies['session']

    def start_session(self, handler):
        """Gives the user a session id and stores it as a cookie in the user's
        browser.

        """
        # Create a unique session id.
        self.session = uuid.uuid4().get_hex()
        # Calculate the date/time for when the session will expire.
        self.expires = datetime.utcnow() + timedelta(days=settings.SESSION_TTL)
        self.put()

        # Build and set a cookie for the session.
        ts = time.strftime('%a, %d-%b-%Y %H:%M:%S GMT',
                           self.expires.timetuple())
        cookie = '%s=%s; expires=%s; path=/' % ('session', self.session, ts)

        # Send cookie to browser.
        handler.response.headers['Set-Cookie'] = cookie
        handler.request.cookies['session'] = self.session


class UserAuthType(polymodel.PolyModel):
    """Represents a method to authenticate to the application.

    """
    user = db.ReferenceProperty(User, collection_name='auth_types',
                                required=True)

    @staticmethod
    def _register(auth_class, display_name, email=None, *args, **kwargs):
        user = User.register(display_name, email)
        auth = auth_class.connect(user, *args, **kwargs)
        return auth

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
    password = db.StringProperty(required=True)

    @staticmethod
    def connect(user, auth_email, password):
        if not isinstance(user, User):
            raise TypeError('Did not get a valid User instance.')

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
    def connect(user):
        if not isinstance(user, User):
            raise TypeError('Did not get a valid User instance.')

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
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    slug = db.StringProperty(required=True, validator=_validate_slug)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    html = db.TextProperty(required=True)

    @staticmethod
    def _create_with_revision(user, slug, title, content, html):
        article = Article(user=user, slug=slug, title=title, content=content,
                          html=html)
        article.put()

        ArticleRevision(parent=article, article=article, user=user, diff='+',
                        content=content, html=html).put()

        return article

    @staticmethod
    def create(user, title, content):
        if not isinstance(user, User):
            raise TypeError('A valid user must be provided.')
        if not isinstance(title, basestring):
            raise TypeError('A valid title must be provided.')
        if not isinstance(content, basestring):
            raise TypeError('A valid article body must be provided.')

        html = markdown2.markdown(content)
        slug = Article.slugify(title)

        return db.run_in_transaction(Article._create_with_revision,
            user, slug, title, content, html)

    @staticmethod
    def slugify(title):
        return re.sub('[^a-z0-9]+', '-', title.lower())

class ArticleRevision(db.Model):
    article = db.ReferenceProperty(Article, collection_name='revisions',
                                   required=True)
    user = db.ReferenceProperty(User, collection_name='revisions',
                                required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    diff = db.TextProperty(required=True)
    content = db.TextProperty(required=True)
    html = db.TextProperty(required=True)
