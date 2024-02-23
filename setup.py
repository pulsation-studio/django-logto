from setuptools import setup, find_packages

setup(
    name='django-logto',
    version='1.0.1',
    packages=find_packages(),
    install_requires=[
        "django>=4.0",
        "djangorestframework>=3.0",
        "python-jose",
        "asgiref",
        "urllib3",
        "logto",
        "requests"
    ],
    author="Pulsation Studio",
    author_email="liam@pulsation.eco",
    description="DRF and Django Logto integration",
    url="https://github.com/pulsation-studio/django-logto"
)
