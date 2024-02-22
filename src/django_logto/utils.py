import base64

import requests
from asgiref.sync import async_to_sync
from django.conf import settings
from django.http import HttpRequest
from .django_logto_client import DjangoLogtoClient
from .models import LogtoUser
from jose import jwt
from logto.models.response import UserInfoResponse
from rest_framework.exceptions import AuthenticationFailed, APIException


def get_authorization_header(request: HttpRequest) -> str:
    auth = request.headers.get("Authorization", '')

    return auth


def decode_token(token: str) -> dict:
    jwks_uri = requests.get(settings.LOGTO_JWKS_URIS)
    issuer = f"{settings.LOGTO_ENDPOINT}/oidc"
    jwks = jwks_uri.json()

    try:
        payload = jwt.decode(
            token,
            jwks,
            # The jwt encode algorithm retrieved along with jwks. ES384 by default
            algorithms=jwt.get_unverified_header(token).get('alg'),
            # The API's registered resource indicator in Logto
            audience=settings.LOGTO_AUDIENCE,
            issuer=issuer,
            options={
                'verify_at_hash': False
            }
        )
    except Exception as e:
        # exception handler
        raise AuthenticationFailed("Invalid token")

    return payload


def get_or_create_admin(logto_user: LogtoUser) -> LogtoUser:
    logto_admin = LogtoUser.objects.filter(sub=logto_user.sub).first()
    if logto_admin is None:
        logto_admin = LogtoUser.objects.create(
            sub=logto_user.sub,
            email=logto_user.email,
            username=logto_user.email
        )
        logto_admin.is_staff = True
        logto_admin.is_active = True
        logto_admin.is_superuser = True
        logto_admin.save()

    return logto_admin


def get_management_api_token():
    app_id = settings.LOGTO_ADMIN_CLIENT_ID
    app_secret = settings.LOGTO_ADMIN_CLIENT_SECRET
    encoded_credentials = base64.b64encode(
        f"{app_id}:{app_secret}".encode()
    ).decode()

    url = f"{settings.LOGTO_ENDPOINT}/oidc/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f"Basic {encoded_credentials}"
    }
    data = {
        'grant_type': 'client_credentials',
        'resource': 'https://default.logto.app/api',
        'scope': 'all'
    }

    response = requests.post(
        url,
        data=data,
        headers=headers
    )

    if response.status_code != 200:
        raise APIException(
            f"DjangoLogto exception on M2M interaction: {response.json()}"
        )
    access_token = response.json()["access_token"]

    return access_token


def get_authenticated_logto_user(client) -> LogtoUser:
    try:
        user_infos: UserInfoResponse = get_user_infos(client)

        access_token = get_management_api_token()
        management_api_url = f"{settings.LOGTO_ENDPOINT}/api/users/{user_infos.sub}"
        management_api_headers = {
            'Authorization': f"Bearer {access_token}"
        }
        user = requests.get(
            url=management_api_url,
            headers=management_api_headers
        ).json()

        user = LogtoUser(
            sub=user['id'],
            email=user['primaryEmail'],
            username=user['primaryEmail']
        )
        return user
    except Exception:
        raise AuthenticationFailed("You must pass by /auth/signin so signup")


def get_authenticated_logto_user_roles(user_infos: LogtoUser) -> list[dict]:
    access_token = get_management_api_token()
    management_api_url = f"{settings.LOGTO_ENDPOINT}/api/users/{user_infos.sub}/roles"
    management_api_headers = {
        'Authorization': f"Bearer {access_token}"
    }

    user_roles = requests.get(
        url=management_api_url,
        headers=management_api_headers
    )

    if user_roles.status_code != 200:
        raise APIException(
            f"DjangoLogto exception on ManagementAPI interaction: {user_roles.json()}"
        )

    return user_roles.json()


def is_user_admin(user_infos: LogtoUser) -> bool:
    user_is_admin = False
    user_roles = get_authenticated_logto_user_roles(user_infos)
    admin_tags = settings.LOGTO_ADMIN_TAGS if settings.LOGTO_ADMIN_TAGS is not None else ["admin"]

    for role in user_roles:
        if role['name'] in admin_tags:
            user_is_admin = True

    return user_is_admin


@async_to_sync
async def get_user_infos(client: DjangoLogtoClient):
    return await client.fetchUserInfo()
