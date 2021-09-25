from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Tuple, Union, Any
from pydantic import BaseModel

from jose import jws
from jose import jwt
from jose import jwe

from jose.exceptions import JWSError
from jose.constants import ALGORITHMS


# all claims
# https://www.iana.org/assignments/jwt/jwt.xhtml#claims
# https://openid.net/specs/openid-connect-core-1_0.html


class Token(BaseModel):
    """
    Acts as a General Purpose JWT
    and OpenID Connect Core 1.0 ID Token
    The ID Token is a security token that contains Claims
    about the Authentication of an End-User
    by an Authorization Server when using a Client

    The following Claims are used within the ID Token for all
    OAuth 2.0 flows used by OpenID Connect
    """

    # Mandatory Fields
    # Expires UTC timestamp
    exp: int

    # Issued At UTC Timestamp
    iat: int

    ###############################
    # Generic Fields
    # JWT ID: Unique token Identifier
    jti: Optional[str]

    #############################
    # Conditionally Binding Fields

    # https scheme that contains scheme and host, and optionally
    # port number and path components and no query or fragment components
    iss: Optional[str]

    # A locally unique and never reassigned identifier within the Issuer for the End-User
    # which is intended to be consumed by the Client
    sub: Optional[str]

    # It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value
    aud: Optional[str]

    # in case access_token is provided
    at_hash: Optional[str]

    #####################################

    # authentication time UTC Timestamp
    auth_time: Optional[int]

    # String value used to associate a Client session with an ID Token,
    # and to mitigate replay attacks
    nonce: Optional[str]

    # Authentication Context Class Reference
    acr: Optional[str]

    # Authentication Methods References
    amr: Optional[List[str]]

    #  Authorized party - the party to which the ID Token was issued.
    #  If present, it MUST contain the OAuth 2.0 Client ID of this party.
    azp: Optional[str]

    # Extra Claims
    eclaims: Optional[Dict[Any, Any]]


class JWTOptions(BaseModel):
    verify_signature: bool = True
    verify_aud: bool = True
    verify_iat: bool = True
    verify_exp: bool = True
    verify_nbf: bool = True
    verify_iss: bool = True
    verify_sub: bool = True
    verify_jti: bool = True
    verify_at_hash: bool = True

    require_aud: bool = False
    require_iat: bool = False
    require_exp: bool = False
    require_nbf: bool = False
    require_iss: bool = False
    require_sub: bool = False
    require_jti: bool = False
    require_at_hash: bool = False

    leeway: int = 0


def exp_create(hours=0, minutes=0, seconds=60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=hours, minutes=minutes,
                                                  seconds=seconds)


def jwt_create(issuer=None,
               subject=None,
               audience=None,
               expires: Optional[datetime] = None) -> Token:
    """
    Initialize a Token, and convenience kwargs for the required and Binding JWT claims.
    Token expires in 60 seconds by default
    """
    if not expires:
        expires = exp_create()

    tk = Token(exp=int(expires.timestamp()), iat=int(datetime.now(timezone.utc).timestamp()))

    if issuer:
        tk.iss = issuer

    if subject:
        tk.sub = subject

    if audience:
        tk.aud = audience

    return tk


def jwt_encode(token: Union[Token, Dict[str, Any]], privkey: Union[str, bytes, Dict[str, str]],
               access_token=None) -> str:
    if isinstance(token, Token):
        token = token.dict(exclude_unset=True)

    encoded_token: str = jwt.encode(token, privkey,
                                    algorithm='RS256',
                                    access_token=access_token)
    return encoded_token


def jwt_decode(token_encoded: str, pubkey: Union[str, bytes, Dict[str, str]],
               issuer=None,
               subject=None,
               audience=None,
               access_token=None,
               jwt_options=None
               ) -> Dict[str, Any]:
    decoded_data: Dict[str, Any] = jwt.decode(token_encoded,
                                              pubkey,
                                              algorithms=['RS256'],
                                              issuer=issuer,
                                              subject=subject,
                                              audience=audience,
                                              access_token=access_token,
                                              options=jwt_options)
    return decoded_data


def jwt_verify_signature(token_encoded: str,
                         pubkey: Union[str, bytes, Dict[str, str]]) -> Tuple[bool, str]:
    """
    verifies the signature of an encoded token, and decodes it anyway.
    Doesn't verify any claims, just the signature VS the token content

    :param token_encoded:
    :param pubkey:
    :return:
    """
    try:
        dt = jws.verify(token_encoded, pubkey, algorithms='RS256', verify=True)
        return True, dt.decode()
    except JWSError:
        dt = jws.verify(token_encoded, pubkey, algorithms='RS256', verify=False)
        return False, dt.decode()


def jwe_encrypt(data: str, pubkey: Union[str, bytes, Dict[str, str]]) -> str:
    ex = bytes(jwe.encrypt(data.encode(), pubkey, algorithm=ALGORITHMS.RSA_OAEP))
    return ex.decode()


def jwe_decrypt(encrypted_data: str, privkey: Union[str, bytes, Dict[str, str]]) -> str:
    decrypted_data: bytes = jwe.decrypt(encrypted_data, privkey)
    return decrypted_data.decode()
