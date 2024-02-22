from django.urls import path

from views import SigninView, CallbackView

urlpatterns = [
    path("signin/", SigninView.as_view(), name="signin"),
    path("callback/", CallbackView.as_view(), name="callback"),
]

