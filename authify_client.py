from hashlib import md5, sha1
from datetime import datetime
from random import random
import json
from urlparse import urlparse, parse_qs

import requests


class AuthifyClientException(Exception):
    pass


class AuthifyClient(object):
    """AuthifyClient"""
    def __init__(self, api_key, api_secret, ip):
        self.base_url = 'https://loginserver1.authify.com'
        self.authify_version = 8.5

        self.api_key = api_key
        self.api_secret = api_secret

        self.ip = ip

    def require_login(self, idp, callback_url):
        """Login/sign the user and return the redirect url"""
        request_token_content = '%s%s%s' % (self.api_key, datetime.now(), random())
        request_token_hash = md5(sha1(request_token_content).hexdigest()).hexdigest()
        url = '%s/request/' % (self.base_url,)
        data = {
            'idp': idp,
            'api_key': self.api_key,
            'secret_key': self.api_secret,
            'authify_request_token': request_token_hash,
            'protocol': 'json',
            'uri': callback_url,
            'ip_add': self.ip,
            'v': self.authify_version,
        }
        requests.post(url, data=data)

        return '%s/tokenidx.php?authify_request_token=%s' % (self.base_url, request_token_hash,)

    def get_response(self):
        """Get a status response about the current state from Authify"""
        url = '%s/json/' % (self.base_url,)
        data = {
            'api_key': self.api_key,
            'secret_key': self.api_secret,
            'authify_checksum': self.authify_checksum,
            'protocol': 'json',
            'uri': '',
            'ip_add': self.ip,
            'v': self.authify_version,
        }

        r = requests.post(url, data=data)
        return json.loads(r.content)

    def send_data_to_authify(self, data_to_store):
        """Store data to sign on Authify"""
        url = '%s/store/' % (self.base_url,)
        data = {
            'extradata': data_to_store,
            'api_key': self.api_key,
            'secret_key': self.api_secret,
            'authify_reponse_token': self.authify_checksum,
            'ip_add': self.ip,
            'v': self.authify_version,
        }
        requests.post(url, data=data)

    def get_state(self):
        """Return the current logged in state from Authify about the user"""
        return self.get_response().get('data')[0].get('state')

    def sign_data(self, idp, data_to_sign, callback_url):
        """Check that user is logged in and send the data to Autify for
        storing. Return the redirect url to the Autify sign page."""
        if not self.get_state() == 'logout':
            raise AuthifyClientException('User is not logged in')

        self.send_data_to_authify(data_to_sign)
        redirect_url = self.require_login(idp, callback_url)
        return redirect_url

    def login_noauth_user(self):
        """Shortcurt method to login a noauth user. Get the Authify checksum
        from the redirect url instead of redirecting the user."""
        # Login user
        login_redirect_url = self.require_login('noauth', self.base_url)

        # Get the Authify checksum from redirect url
        r = requests.get(login_redirect_url)
        authify_checksum = parse_qs(urlparse(r.url).query)['authify_response_token'][0]
        self.authify_checksum = authify_checksum

    def is_logged_in(self):
        """Return the current logged in state of the user"""
        if self.get_state() == 'logout':
            return True
        else:
            return False
