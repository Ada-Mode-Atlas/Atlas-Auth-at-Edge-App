import json
import re
import time
import urllib.request
from typing import Literal
from urllib.parse import unquote, urljoin

import boto3
import requests
from jose import jwk, jwt
from jose.utils import base64url_decode


def get_parameters(namespace: str):
    ssm_client = boto3.client("ssm", region_name="us-east-1")
    param = ssm_client.get_parameter(Name=f"/{namespace}/auth/config")
    __OPENID_CONFIGURATION_URL__ = param["Parameter"]["Value"]

    param = ssm_client.get_parameter(Name=f"/{namespace}/auth/redirect")
    __REDIRECT_PATH__ = param["Parameter"]["Value"]

    param = ssm_client.get_parameter(Name=f"/{namespace}/auth/client_id")
    __CLIENT_ID__ = param["Parameter"]["Value"]

    return __OPENID_CONFIGURATION_URL__, __REDIRECT_PATH__, __CLIENT_ID__


def get_openid_config(url: str) -> dict:
    with urllib.request.urlopen(url) as f:
        response = f.read()
    return json.loads(response.decode("utf-8"))


def get_jkws(config: dict) -> list:
    with urllib.request.urlopen(config["jwks_uri"]) as f:
        response = f.read()
    keys = json.loads(response.decode("utf-8"))["keys"]

    return keys


def request_refresh(client_id: str, refresh_token: str, config: dict) -> tuple[str, str, str]:
    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    res = requests.post(config["token_endpoint"], params=payload, headers=headers)
    try:
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise Exception(f"HTTP error occurred ({res.json()}): {e}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"A request error occurred ({res.json()}): {e}")

    jwt = res.json()

    id_token = jwt.get("id_token", "")
    access_token = jwt["access_token"]
    refresh_token = jwt.get("refresh_token", refresh_token)

    return id_token, access_token, refresh_token


def request_token(code: str, client_id: str, redirect_uri: str, config: dict) -> tuple[str, str, str]:
    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    res = requests.post(config["token_endpoint"], params=payload, headers=headers)
    try:
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise Exception(f"HTTP error occurred ({res.json()}): {e}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"A request error occurred ({res.json()}): {e}")

    jwt = res.json()

    id_token = jwt.get("id_token", "")
    access_token = jwt["access_token"]
    refresh_token = jwt.get("refresh_token", "")

    return id_token, access_token, refresh_token


def request_signin(client_id: str, state: str, redirect_uri: str, config: dict) -> dict:
    response = {
        "status": "307",
        "statusDescription": "Temporary Redirect",
        "headers": {
            "location": [
                {
                    "key": "location",
                    "value": f"{config['authorization_endpoint']}?client_id={client_id}&response_type=code&scope=email+openid+phone+profile&redirect_uri={redirect_uri}&state={state}",
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
                "value": f"ATLAS_ID_TOKEN={id_token}; Path=/; Secure; HttpOnly;",
            }
        )

    if access_token:
        cookie_list.append(
            {
                "key": "Set-Cookie",
                "value": f"ATLAS_ACCESS_TOKEN={access_token}; Path=/; Secure; HttpOnly;",
            }
        )

    if refresh_token:
        cookie_list.append(
            {
                "key": "Set-Cookie",
                "value": f"ATLAS_REFRESH_TOKEN={refresh_token}; Path=/; Secure; HttpOnly;",
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


def verify_token(access_token: str, jwks: list) -> Literal["REFRESH", "SIGNIN", "CONTINUE"]:
    if not access_token:
        return "SIGNIN"

    jwtHeaders = jwt.get_unverified_headers(access_token)
    kid = jwtHeaders["kid"]

    key_index = -1
    for i in range(len(jwks)):
        if kid == jwks[i]["kid"]:
            key_index = i
            break
    if key_index == -1:
        raise Exception("Public key not found in jwks.json")

    publicKey = jwk.construct(jwks[key_index])

    message, encoded_signature = str(access_token).rsplit(".", 1)
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    if not publicKey.verify(message.encode("utf8"), decoded_signature):
        raise Exception("Signature verification failed")

    claims = jwt.get_unverified_claims(access_token)
    if time.time() > claims["exp"]:
        return "REFRESH"

    return "CONTINUE"


def _build_redirect_uri(request: dict, redirect_path: str) -> str:
    host = request["headers"]["host"][0]["value"]
    return urljoin(f"https://{host}", redirect_path)
    # return "https://hub.ada-atlas.com/auth/callback"


def _build_uri(request: dict) -> str:
    host = request["headers"]["host"][0]["value"]
    uri = request["uri"]
    query = request.get("querystring", "")

    url = f"https://{host}{uri}?{query}" if query else f"https://{host}{uri}"

    return url


def _extract_namespace(fn_name) -> str:
    # Expecting format like "auth-handler-prod"
    match = re.search(r"auth-(?:handler|callback)-([a-zA-Z0-9_-]+)", fn_name)
    return match.group(1) if match else "default"


def auth_handler(event: dict, context) -> dict:
    __OPENID_CONFIGURATION_URL__, __REDIRECT_PATH__, __CLIENT_ID__ = get_parameters(
        namespace=_extract_namespace(context.function_name)
    )
    __CONFIG__ = get_openid_config(url=__OPENID_CONFIGURATION_URL__)
    __JWKS__ = get_jkws(config=__CONFIG__)

    request = event["Records"][0]["cf"]["request"]
    headers = request["headers"]

    id_token, access_token, refresh_token = get_cookies(headers)

    try:
        action = verify_token(id_token, jwks=__JWKS__)
    except Exception:
        return {
            "status": "403",
            "statusDescription": "Forbidden",
            "body": "Invalid token",
        }

    if action == "CONTINUE":
        return request

    elif action == "REFRESH":
        try:
            id_token, access_token, refresh_token = request_refresh(
                client_id=__CLIENT_ID__, refresh_token=refresh_token, config=__CONFIG__
            )
        except Exception as _:
            return request_signin(
                client_id=__CLIENT_ID__,
                state=_build_uri(request),
                redirect_uri=_build_redirect_uri(request, __REDIRECT_PATH__),
                config=__CONFIG__,
            )
        else:
            return set_cookies(
                request=request, id_token=id_token, access_token=access_token, refresh_token=refresh_token
            )

    elif action == "SIGNIN":
        return request_signin(
            client_id=__CLIENT_ID__,
            state=_build_uri(request),
            redirect_uri=_build_redirect_uri(request, __REDIRECT_PATH__),
            config=__CONFIG__,
        )
    else:
        raise ValueError("Action type is not supported")


def callback_handler(event: dict, context) -> dict:
    __OPENID_CONFIGURATION_URL__, __REDIRECT_PATH__, __CLIENT_ID__ = get_parameters(
        namespace=_extract_namespace(context.function_name)
    )
    __CONFIG__ = get_openid_config(url=__OPENID_CONFIGURATION_URL__)

    request = event["Records"][0]["cf"]["request"]
    qs = request["querystring"]
    query_params = dict(q.split("=") for q in qs.split("&"))

    id_token, access_token, refresh_token = request_token(
        code=query_params["code"],
        client_id=__CLIENT_ID__,
        redirect_uri=_build_redirect_uri(request, __REDIRECT_PATH__),
        config=__CONFIG__,
    )
    target_uri = unquote(query_params["state"])
    response = {
        "status": "302",
        "statusDescription": "Found",
        "headers": {
            "location": [
                {
                    "key": "location",
                    "value": target_uri,
                },
            ]
        },
    }

    return set_cookies(response, id_token=id_token, access_token=access_token, refresh_token=refresh_token)
