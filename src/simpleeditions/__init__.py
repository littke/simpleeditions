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

class Error(Exception):
    """Generic error for the SimpleEditions application."""

class ConnectError(Error):
    """Raised when connecting an authentication type to a user fails."""

class ExternalLoginNeededError(Error):
    """Raised when a login cannot be completed without leaving the page.

    It's up to the code handling the error to decide whether to send the
    user to another page or to return an error.

    """

class LogInError(Error):
    """Error raised when logging in fails."""

class NotConnectedError(Error):
    """Raised when a user is validated by the external service, but does not
    have a corresponding application account.

    """

class NotLoggedInError(Error):
    """Raised when the user needs to be logged in, but isn't."""

class NotFoundError(Error):
    """Raised when a resource could not be found."""

class ArticleNotFoundError(NotFoundError):
    """Raised when an article cannot be found."""

class RevisionNotFoundError(NotFoundError):
    """Raised when a revision cannot be found."""

class UserNotFoundError(NotFoundError):
    """Raised when a user cannot be found."""

class ReadOnlyError(Error):
    """Raised when attempting to modify a resource that is read only."""

class RegisterError(Error):
    """Raised when registration fails."""

class SaveError(Error):
    """Raised when saving a resource fails."""

class SaveArticleError(SaveError):
    """Raised when saving an article fails."""

class SaveBlobError(SaveError):
    """Raised when uploading a file fails."""

class SaveCommentError(SaveError):
    """Raised when adding a comment fails."""
