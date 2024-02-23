from django.http import HttpRequest
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .django_logto_client import DjangoLogtoClient
from .logto_init import start_logto_client
from .models import LogtoUser
from .utils import get_authenticated_logto_user, get_authorization_header, decode_token


class LogtoAuthentication(BaseAuthentication):
    def authenticate(self, request: HttpRequest):
        if request.accepted_renderer.format == 'api':
            client: DjangoLogtoClient = start_logto_client(request)
            authenticated_user = get_authenticated_logto_user(client)
            return authenticated_user, None

        auth: list[str] = get_authorization_header(request).split()

        if not auth or auth[0].lower() != "bearer":
            return None

        if len(auth) < 2:
            raise AuthenticationFailed("Invalid token format")

        elif auth[0] != 'Bearer':
            raise AuthenticationFailed("Token type not supported")

        decoded_token: dict = decode_token(auth[1])

        user_sub: str = decoded_token.get('sub')

        user = LogtoUser(
            sub=user_sub,
            username=None
        )

        return user, None
