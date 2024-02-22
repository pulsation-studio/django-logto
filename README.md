# External and BrowsableAPI Authentication
This README.md assumes that you already set up a Logto app for your front-end application. \
First at all, use the command `python manage.py migrate` to change the user model. \
You will now have to add the logto urls:
````python
url_patterns = [
    path('auth/', include('django_logto.urls')),
]
````

To use External Authentication and BrowsableAPI authentication, you need to change the default Authenticationclass in your settings. \
```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        "django_logto.authentication.LogtoAuthentication",
    ),
}
```

You need to set in settings.py:
```python
LOGTO_AUDIENCE="**your_api_url**" #(e.g. : http://localhost:8000)
LOGTO_JWKS_URIS="**<logto_url>/oidc/jwks**"
LOGTO_ENDPOINT="**your_logto_url**"
LOGTO_API_CLIENT_ID="**your_TraditionalWebApp_id**"
LOGTO_API_SECRET="**your_TraditionalWebApp_secret**"
LOGTO_API_REDIRECT_URI="**<your_api_url>/auth/callback/**"
LOGTO_CALLBACK_URI="**<your_api_url>/api/**" #(this one can be changed, depending on your needs. For more information, you can refer to the Logto documentation )
```

For BrowsableAPI authentication, you can authenticate threw /auth/signin

# DjangoAdmin Authentication
Set the `AUTH_USER_MODEL` and `AUTHENTICATION_BACKENDS` in settings: \
````python
AUTHENTICATION_BACKENDS = ["django_logto.logto_backend.LogtoBackend"]
AUTH_USER_MODEL = "django_logto.LogtoUser"
````

Add the related Machine-To-Machine Logto app environment variables:
```python
LOGTO_ADMIN_CLIENT_ID="**<your_m2m_app_id>**"
LOGTO_ADMIN_CLIENT_SECRET="**<your_m2m_app_secret>**"
```

> This package accesses to Logto ManagementAPI to retrieve the actual connected user's roles. \
You will need to give your M2M app the permission to access to ManagementAPI (don't forget to set the role as "Machine-to-machine app role"): \
https://docs.logto.io/docs/recipes/rbac/manage-permissions-and-roles/#create-and-define-a-new-role 

> This package also expects (by default) to receive an "admin" role from the managementAPI to give the user the right to access the admin console by creating a role with name="admin" (don't forget to set the role as "User role"). \
> You can override it by defining another admin tags in settings.py: \
```python
LOGTO_ADMIN_TAG=["<1st_admin_tag>","<2nd_admin_tag>","etc"]
```