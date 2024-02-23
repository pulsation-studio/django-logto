from setuptools import setup, find_packages
with open('README.md', 'r') as file:
    long_description = file.read()

setup(
    name='django-logto',
    version='1.0.4',
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
    url="https://github.com/pulsation-studio/django-logto",
    long_description=long_description,
    long_description_content_type="text/markdown"
)
