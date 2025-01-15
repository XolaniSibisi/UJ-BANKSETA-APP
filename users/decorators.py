from functools import wraps

from flask import flash, redirect, request, url_for
from flask_login import current_user



def authentication_redirect(func):
    """
    Decorator to redirect authenticated users to the index page.
    """

    @wraps(func)
    def decorator_func(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for("users.home"))
        return func(*args, **kwargs)

    return decorator_func