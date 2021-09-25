

from typing import Dict, List, Optional, Any

from pydantic import BaseModel

import requests

# Examples of Google Certificates, and Google OpenID Connect Meta data
_gcerts = {
    'keys': [{
        'kty': 'RSA',
        'n': 'xYm1YQcXmVA0ZoevzgGlFKUzFPiBlbVemTE5ZvWp-n-4tQjMiLnfMVq3Nm9j7ecS2THP6v99ds_fI8ko'
             '-az4nvO1KjNZTEIdj_nvCbJvap0O'
             '-4nRGg6aRFMRCqrm1N0U7xk2cIOO61ap0kLnyeuEo2WLhOycdTqDEh6fDY7lHwWYe1k9Vnfu51odPxzOXGG5dnQZL8syu_'
             '64bNL3RiUL__LHr31GZuxrpBg-bRu7MauYqV6A17jtRiSxZ02OZRt3apmHBy9zpqsorDCeOXwChqKaLuaCNJFHpsYAaM97ODcRz2Ga'
             'FItH6uUw4KprqGqhulk8VIBWjonqQzY2dC9pyw',
        'e': 'AQAB',
        'alg': 'RS256',
        'use': 'sig',
        'kid': 'de9556ad4680312c117afaef2920f5f99a4c79fd'
    }, {
        'alg': 'RS256',
        'kid': '77209104ccd890a5aedd6733e0252f54e882f13c',
        'use': 'sig',
        'e': 'AQAB',
        'kty': 'RSA',
        'n': 'x7--mXPc9umyDBi1pOK4kKHonfa7-mNmKo10W1iAyHVjAfdM8NDPDRbwazZLLQhBvyAe2DotMbgVFYSWQMhT883w9Kn'
             '-2dzoTHlYB1qyd82Coc7jKeHcde54Zjay-8Pzjioa7-Dj7vuNyIHojtJcqDqslWCDfi-Tm'
             '-g67cqxaoZ34gDSlhTKFlzoLYufUaVG4lSxNWxV6YiwZshabmngwKFcYJGL4zWhA48oB8cVf9fFT'
             '-gtnk1hUJ95VD41jpzWCXPupIQvPRDmiY_mKcmc6GE2YAqABAx30oCflV-UznmlymLGqsUTnJ26OiiIe5zpbivW0Qi7bLwHs-vm'
             '-5dS3Q '
    }]
}

_gauth_meta = {
    'issuer': 'https://accounts.google.com',
    'authorization_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
    'device_authorization_endpoint': 'https://oauth2.googleapis.com/device/code',
    'token_endpoint': 'https://oauth2.googleapis.com/token',
    'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
    'revocation_endpoint': 'https://oauth2.googleapis.com/revoke',
    'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs',
    'response_types_supported': [
        'code', 'token', 'id_token', 'code token', 'code id_token',
        'token id_token', 'code token id_token', 'none'
    ],
    'subject_types_supported': ['public'],
    'id_token_signing_alg_values_supported': ['RS256'],
    'scopes_supported': ['openid', 'email', 'profile'],
    'token_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic'],
    'claims_supported': [
        'aud', 'email', 'email_verified', 'exp', 'family_name', 'given_name',
        'iat', 'iss', 'locale', 'name', 'picture', 'sub'
    ],
    'code_challenge_methods_supported': ['plain', 'S256'],
    'grant_types_supported': [
        'authorization_code', 'refresh_token',
        'urn:ietf:params:oauth:grant-type:device_code',
        'urn:ietf:params:oauth:grant-type:jwt-bearer'
    ]
}
#######################################################################################


class GauthMeta(BaseModel):
    issuer: str
    authorization_endpoint: str
    device_authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    revocation_endpoint: str
    jwks_uri: str
    response_types_supported: List[str]
    subject_types_supported: List[str]
    id_token_signing_alg_values_supported: List[str]
    scopes_supported: List[str]
    token_endpoint_auth_methods_supported: List[str]
    claims_supported: List[str]
    code_challenge_methods_supported: List[str]
    grant_types_supported: List[str]


class GoogleToken(BaseModel):
    aud: str

    exp: int

    iat: int

    iss: str

    sub: str

    at_hash: Optional[str]

    azp: Optional[str]

    email: Optional[str]

    email_verified: Optional[bool]

    family_name: Optional[str]

    given_name: Optional[str]

    # Hosted G-Suite Domain of the user
    hd: Optional[str]

    locale: Optional[str]

    name: Optional[str]

    nonce: Optional[str]

    picture: Optional[str]

    profile: Optional[str]


def load_gauth_meta() -> GauthMeta:
    gauth_meta = requests.get(
        "https://accounts.google.com/.well-known/openid-configuration").json()
    return GauthMeta.parse_obj(gauth_meta)


def load_google_jwks(meta: GauthMeta) -> Dict[str, List[Any]]:
    return requests.get(meta.jwks_uri).json()
