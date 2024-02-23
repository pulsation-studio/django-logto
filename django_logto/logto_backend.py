from django.contrib.auth.backends import BaseBackend
from rest_framework.exceptions import PermissionDenied

from .logto_init import start_logto_client
from .models import LogtoUser
from .utils import get_authenticated_logto_user, is_user_admin, get_or_create_admin


class LogtoBackend(BaseBackend):

    def authenticate(self, request, **kwargs):
        client = start_logto_client(request)
        logto_user: LogtoUser = get_authenticated_logto_user(client)
        user_is_admin = is_user_admin(logto_user)

        if user_is_admin:
            return get_or_create_admin(logto_user)
        else:
            raise PermissionDenied("You don't have the permissions to access Admin console")

    def get_user(self, user_id):
        logto_admin = LogtoUser.objects.filter(id=user_id).first()
        return logto_admin

    def has_perm(self, user_obj, perm, obj=None):
        return user_obj.is_admin and user_obj.is_authenticated
