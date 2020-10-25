import base64
import json
import logging

from urllib.parse import parse_qs

import requests
from OpenSSL.crypto import verify, load_publickey, FILETYPE_PEM, X509
from OpenSSL.crypto import Error as SignatureError

from django.conf import settings
from django.views.generic import View
from django.http import HttpResponseBadRequest, JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'console': {
            'format': '%(name)-12s %(levelname)-8s %(message)s'
        },
        'file': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'console'
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'formatter': 'file',
            'filename': '/tmp/debug.log'
        }
    },
    'loggers': {
        '': {
            'level': 'DEBUG',
            'handlers': ['console', 'file']
        }
    }
})

class Travis(View):

    # Make sure you use the correct config URL, the .org and .com
    # have different keys!
    # https://api.travis-ci.org/config
    # https://api.travis-ci.com/config
    TRAVIS_CONFIG_URL = settings.TRAVIS_CONFIG_URL
    logger.info(TRAVIS_CONFIG_URL)

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(Travis, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logger.info('POST Requested')
        signature = self._get_signature(request)
        json_payload = parse_qs(request.body)['payload'][0]
        logger.info('JSON Parsed')
        try:
            public_key = self._get_travis_public_key()
        except requests.Timeout:
            logger.error({"message": "Timed out when attempting to retrieve Travis CI public key"})
            return HttpResponseBadRequest({'status': 'failed'})
        except requests.RequestException as e:
            logger.error({"message": "Failed to retrieve Travis CI public key", 'error': e.message})
            return HttpResponseBadRequest({'status': 'failed'})
        try:
            self.check_authorized(signature, public_key, json_payload)
        except SignatureError:
            # Log the failure somewhere
            return HttpResponseBadRequest({'status': 'unauthorized'})
        json_data = json.loads(json_payload)
        logger.info('####################')
        logger.info(json_data)
        logger.info('####################')
        return JsonResponse({'status': 'received'})

    def check_authorized(self, signature, public_key, payload):
        """
        Convert the PEM encoded public key to a format palatable for pyOpenSSL,
        then verify the signature
        """
        pkey_public_key = load_publickey(FILETYPE_PEM, public_key)
        certificate = X509()
        certificate.set_pubkey(pkey_public_key)
        verify(certificate, signature, payload, str('sha1'))

    def _get_signature(self, request):
        """
        Extract the raw bytes of the request signature provided by travis
        """
        signature = request.META['HTTP_SIGNATURE']
        return base64.b64decode(signature)

    def _get_travis_public_key(self):
        """
        Returns the PEM encoded public key from the Travis CI /config endpoint
        """
        response = requests.get(self.TRAVIS_CONFIG_URL, timeout=10.0)
        response.raise_for_status()
        return response.json()['config']['notifications']['webhook']['public_key']
