"""
Authify Client example usage in Django

1. Move authify_client.py to project dir or global site-packages dir.
2. Django example usage. Sign with BankID E-legitimation in a Django view:
"""

from django.conf import settings
from django.shortcuts import redirect
from authify_client import AuthifyClient


def authify_client_view(request):
    AUTHIFY_API_KEY = getattr(settings, 'AUTHIFY_API_KEY', '')
    AUTHIFY_API_SECRET = getattr(settings, 'AUTHIFY_API_SECRET', '')
    authify_checksum = request.GET.get('authify_response_token')

    authify_client = AuthifyClient(
        api_key=AUTHIFY_API_KEY,
        api_secret=AUTHIFY_API_SECRET,
        ip=get_client_ip(request),
    )

    # Redirect and login the user to Authify
    if (not request.GET.get('from_authify') == '1' and
        not authify_checksum):
            callback_url = request.build_absolute_uri()
            return redirect(
                authify_client.require_login('noauth', callback_url)
            )
    # User is logged in to Authify, send the user to Authify to sign
    elif (request.GET.get('from_authify') == '1' and
          len(authify_checksum) == 44):
            authify_client.authify_checksum = authify_checksum
            # The Authify checksum is valid and user is logged in
            if authify_client.is_logged_in():
                sign_type = 'bankid_sign'
                sign_url = authify_client.sign_data(
                    sign_type,
                    data_to_sign='DATA_TO_SIGN',
                    callback_url='http://callback.url')
                return redirect(sign_url)
