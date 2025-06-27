import json
import time
import urllib.request
from typing import Literal
from urllib.parse import quote, unquote, urljoin

import boto3
import requests
from jose import jwk, jwt
from jose.utils import base64url_decode

ssm_client = boto3.client("ssm", region_name="us-east-1")
param = ssm_client.get_parameter(Name="/prod/auth/config")
__OPENID_CONFIGURATION_URL__ = param["Parameter"]["Value"]

param = ssm_client.get_parameter(Name="/prod/auth/redirect")
__REDIRECT_PATH__ = param["Parameter"]["Value"]

param = ssm_client.get_parameter(Name="/prod/auth/client_id")
__CLIENT_ID__ = param["Parameter"]["Value"]


def get_config() -> dict:
    with urllib.request.urlopen(__OPENID_CONFIGURATION_URL__) as f:
        response = f.read()
    return json.loads(response.decode("utf-8"))


__CONFIG__ = get_config()


def get_jkws() -> dict:
    with urllib.request.urlopen(__CONFIG__["jwks_uri"]) as f:
        response = f.read()
    keys = json.loads(response.decode("utf-8"))["keys"]

    return keys


__JWKS__ = get_jkws()


def request_refresh(client_id: str, refresh_token: str) -> tuple[str, str, str]:
    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    res = requests.post(__CONFIG__["token_endpoint"], params=payload, headers=headers)
    jwt = res.json()

    id_token = jwt["id_token"]
    access_token = jwt["access_token"]
    refresh_token = jwt.get("refresh_token", refresh_token)

    return id_token, access_token, refresh_token


def request_token(code: str, client_id: str, redirect_uri: str) -> tuple[str, str, str]:
    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    res = requests.post(__CONFIG__["token_endpoint"], params=payload, headers=headers)
    jwt = res.json()

    id_token = jwt.get("id_token", "")
    access_token = jwt["access_token"]
    refresh_token = jwt.get("refresh_token", "")

    return id_token, access_token, refresh_token


def request_signin(client_id: str, state: str, redirect_uri: str) -> dict:
    response = {
        "status": "307",
        "statusDescription": "Temporary Redirect",
        "headers": {
            "location": [
                {
                    "key": "location",
                    "value": f"{__CONFIG__['authorization_endpoint']}?client_id={client_id}&response_type=code&scope=email+openid+phone+profile&redirect_uri={redirect_uri}&state={state}",
                },
            ],
        },
    }

    return response


def set_cookies(request: dict, id_token: str, access_token: str, refresh_token: str) -> dict:
    cookie_list = request["headers"].get("set-cookie", [])

    if id_token:
        cookie_list.append(
            {
                "key": "Set-Cookie",
                "value": f"ATLAS_ID_TOKEN={id_token}",
                "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax",
            }
        )

    if access_token:
        cookie_list.append(
            {
                "key": "Set-Cookie",
                "value": f"ATLAS_ACCESS_TOKEN={access_token}",
                "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax",
            }
        )

    if refresh_token:
        cookie_list.append(
            {
                "key": "Set-Cookie",
                "value": f"ATLAS_REFRESH_TOKEN={refresh_token}",
                "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax",
            }
        )

    if len(cookie_list) > 0:
        request["headers"]["set-cookie"] = cookie_list

    return request


def get_cookies(headers: dict) -> tuple[str, str, str]:
    id_token = ""
    access_token = ""
    refresh_token = ""

    for cookie in headers.get("cookie", []):
        cookiesList = cookie["value"].split(";")
        for subCookie in cookiesList:
            if "ATLAS_ID_TOKEN" in subCookie:
                id_token = subCookie.split("=")[1]

            if "ATLAS_ACCESS_TOKEN" in subCookie:
                access_token = subCookie.split("=")[1]

            if "ATLAS_REFRESH_TOKEN" in subCookie:
                refresh_token = subCookie.split("=")[1]

    return id_token, access_token, refresh_token


def verify_token(id_token: str) -> Literal["REFRESH", "SIGNIN", "CONTINUE"]:
    if not id_token:
        return "SIGNIN"

    jwtHeaders = jwt.get_unverified_headers(id_token)
    kid = jwtHeaders["kid"]

    key_index = -1
    for i in range(len(__JWKS__)):
        if kid == __JWKS__[i]["kid"]:
            key_index = i
            break
    if key_index == -1:
        raise Exception("Public key not found in jwks.json")

    publicKey = jwk.construct(__JWKS__[key_index])

    message, encoded_signature = str(id_token).rsplit(".", 1)
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    if not publicKey.verify(message.encode("utf8"), decoded_signature):
        raise Exception("Signature verification failed")

    claims = jwt.get_unverified_claims(id_token)
    if time.time() > claims["exp"]:
        return "REFRESH"

    return "CONTINUE"


def _build_redirect_uri(request: dict) -> str:
    host = request["headers"]["host"][0]["value"]
    return quote(urljoin(f"https://{host}", __REDIRECT_PATH__), safe="")


def _build_uri(request: dict) -> str:
    host = request["headers"]["host"][0]["value"]
    uri = request["uri"]
    query = request.get("querystring", "")

    url = f"https://{host}{uri}?{query}" if query else f"https://{host}{uri}"

    return quote(url, safe="")


def auth_handler(event: dict, context: dict) -> dict:
    request = event["Records"][0]["cf"]["request"]
    headers = request["headers"]

    id_token, access_token, refresh_token = get_cookies(headers)

    try:
        action = verify_token(id_token)
    except Exception:
        return {
            "status": "403",
            "statusDescription": "Forbidden",
            "body": "Invalid token",
        }

    if action == "CONTINUE":
        return request

    elif action == "REFRESH":
        id_token, access_token, refresh_token = request_refresh(client_id=__CLIENT_ID__, refresh_token=refresh_token)
        return set_cookies(request=request, id_token=id_token, access_token=access_token, refresh_token=refresh_token)

    elif action == "SIGNIN":
        return request_signin(
            client_id=__CLIENT_ID__,
            state=_build_uri(request),
            redirect_uri=_build_redirect_uri(request),
        )
    else:
        raise ValueError("Action type is not supported")


def callback_handler(event: dict, context: dict) -> dict:
    request = event["Records"][0]["cf"]["request"]
    qs = request["querystring"]
    query_params = dict(q.split("=") for q in qs.split("&"))

    id_token, access_token, refresh_token = request_token(
        code=query_params["code"],
        client_id=__CLIENT_ID__,
        redirect_uri=_build_redirect_uri(request),
    )

    response = {
        "status": "307",
        "statusDescription": "Temporary Redirect",
        "headers": {
            "location": [
                {
                    "key": "location",
                    "value": unquote(query_params["state"]),
                },
            ]
        },
    }

    return set_cookies(response, id_token=id_token, access_token=access_token, refresh_token=refresh_token)
