"""Python Version 3.5.2."""
from hashlib import sha1
import base64
import collections
import data
import hmac
import random
import requests
import time
import urllib
"""
    shal to use hash method
    base64 to convert signature to base64
    collections to make sort to parameters
    data file that have consumer_secret , consumer_key , urls
    hmac to hash key and base_string
    random to generate random string
    requests to make Http requests
    time to generate timestamp
    urllib to make Percent encode
"""


def encode(text):
    """Percent encode."""
    return urllib.parse.quote(str(text), "")


def get_nonce():
    """Unique nonce generated for each request. of len 10 [0,9]."""
    str1 = (''.join([str(random.randint(0, 9)) for i in range(10)]))
    return str1


def create_parameters_string(parameters):
    """Create parameters_string to create base_string."""
    """
        Sort the list of parameters alphabetically
        Append the encoded key to the output string
        Append the ‘=’ character to the output string
        Append the encoded value to the output string
        append a ‘&’ character to the output string between parameters
    """
    output = ''
    ordered_parameters = {}
    ordered_parameters = collections.OrderedDict(sorted(parameters.items()))
    for k, v in ordered_parameters.items():
        output += ('%s%s%s%s' % (encode(k), '=', encode(v), '&'))
    return output[:len(output) - 1]


def create_base_string(method, url, paramters):
    """Make Method uppercase ,encode url , paramters and add all together."""
    method = method.upper()
    url = encode(url)
    paramters = encode(paramters)
    return ('%s%s%s%s%s') % (method, '&', url, '&', paramters)


def create_signature(key, base_string):
    """Create signature with key and base_string."""
    """
     Percent encoded consumer_secret and add to '&'.
     Percent encoded OAuth token secret and add to string key "if known"
     convert key , base_string to bytes (required from hash).
     make hash to key , base_string with (shal hash).
     convert hashed to base64.
     encode base64.
     """
    key = key + '&'
    key = bytes(key, 'UTF-8')
    base_string = bytes(base_string, 'UTF-8')
    hashed = hmac.new(key, base_string, sha1).digest()
    return encode(str(base64.b64encode(hashed), 'UTF-8'))


def create_paramters(parmeters):
    """Add OAuth and all parmeters together to be value to Authorization."""
    headers = 'OAuth '
    for i in parmeters:
        headers += '%s%s%s%s' % (i[0], '="', i[1], '",')
    return headers


def get_headers(consumer_key, consumer_secret):
    """Create Headers and signature ."""
    paramters = {
        'oauth_nonce': get_nonce(),
        'oauth_timestamp': int(time.time()),
        'oauth_version': '1.0',
        'oauth_signature_method': 'HMAC-SHA1',
        'oauth_consumer_key': consumer_key,
    }
    parameters_string = create_parameters_string(paramters)
    base_string = create_base_string('post', data.url, parameters_string)
    signature = create_signature(encode(consumer_secret), base_string)
    lis = [
        ('oauth_consumer_key', consumer_key),
        ('oauth_signature_method', 'HMAC-SHA1'),
        ('oauth_timestamp', paramters['oauth_timestamp']),
        ('oauth_nonce', paramters['oauth_nonce']),
        ('oauth_version', '1.0'),
        ('oauth_signature', signature),
    ]
    headers = {
        'Authorization': (create_paramters(lis)),
    }
    return headers


def get_tokens(content):
    """Split response to auth_token, auth_token_secret and return 2 in list."""
    content = str(content)
    response = content.split('&')
    tokens = {
        'auth_token': response[0].split('=')[1],
        'auth_token_secret': response[1].split('=')[1],
    }
    return tokens


def get_authorize_url(consumer_key, consumer_secret):
    """Get Authorization url."""
    headers = get_headers(consumer_key, consumer_secret)
    response = requests.post(data.url, headers=headers)
    tokens = get_tokens(response.content)
    return ("%s%s") % (data.urlotherize, str(tokens['auth_token']))
