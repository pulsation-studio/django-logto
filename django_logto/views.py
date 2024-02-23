import os

from django.http import HttpResponseRedirect, HttpResponse
from django.views import View

from .logto_init import start_logto_client


class SigninView(View):
    async def get(self, request):
        uri = os.environ.get("LOGTO_API_REDIRECT_URI")
        client = start_logto_client(request)
        url = await client.signIn(redirectUri=uri)
        return HttpResponseRedirect(redirect_to=url)


class CallbackView(View):
    async def get(self, request):
        absolute_uri = request.build_absolute_uri()
        client = start_logto_client(request)
        try:
            await client.handleSignInCallback(absolute_uri)
            return HttpResponseRedirect(
                redirect_to=os.environ.get("LOGTO_CALLBACK_URI")
            )
        except Exception as e:
            return HttpResponse("Error: " + str(e))
