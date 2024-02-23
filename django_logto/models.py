from django.contrib.auth.models import AbstractUser
from django.db import models


class LogtoUser(AbstractUser):
    sub = models.CharField(max_length=20)