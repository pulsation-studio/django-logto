import os

from asgiref.sync import async_to_sync, sync_to_async
from django.http import HttpRequest
from django.conf import settings
from logto import Storage, LogtoConfig

from django_logto_client import DjangoLogtoClient


class SessionStorage(Storage):

    def __init__(self, request: HttpRequest):
        self.request = request

    @sync_to_async
    def get(self, key: str):
        return self.request.session.get(key, '')

    @sync_to_async
    def set(self, key: str, value: str | None) -> None:
        self.request.session.__setitem__(key, value)

    @sync_to_async
    def delete(self, key: str) -> None:
        if key in self.request.session:
            self.request.session.__delitem__(key)


def start_logto_client(request: HttpRequest):
    client = DjangoLogtoClient(
        LogtoConfig(
            endpoint=f"{settings.LOGTO_ENDPOINT}/",
            appId=settings.LOGTO_API_CLIENT_ID,
            appSecret=settings.LOGTO_API_SECRET
        ),
        storage=SessionStorage(request)
    )
    return client


@async_to_sync
async def get_user_infos(client: DjangoLogtoClient):
    return await client.fetchUserInfo()
