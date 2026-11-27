import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, quote_plus, urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
import requests


def expect(response, status, error=None):
    assert response.status_code == status, (
        response.request.method, urlparse(response.url).path, response.status_code, status
    )
    if error:
        assert response.json()["error"] == error
    return response


def encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def session_id(token_response):
    payload = token_response["access_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims.get("sid") or claims["session_state"]


def proof(key, method, url, token=None):
    public = key.public_key().public_numbers()
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": {
        "kty": "EC", "crv": "P-256", "x": encode(public.x.to_bytes(32, "big")),
        "y": encode(public.y.to_bytes(32, "big")),
    }}
    claims = {"jti": secrets.token_urlsafe(), "htm": method, "htu": url, "iat": int(time.time())}
    if token is not None:
        claims["ath"] = encode(sha256(token.encode()).digest())
    unsigned = ".".join(encode(json.dumps(part).encode()) for part in (header, claims))
    signature = key.sign(unsigned.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    return unsigned + "." + encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def check_sso(base, certificate, admin_password):
    realm = "/realms/sso-it"
    admin_realm = "/admin" + realm
    oidc = realm + "/protocol/openid-connect"
    init_path = realm + "/sso/init"
    challenge_path = realm + "/sso/challenge"
    client = "sso-it-client"
    other_client = "sso-it-other-client"
    secret = "a:+%/" + secrets.token_urlsafe()
    password = secrets.token_urlsafe()
    state = "идентификатор + & / %"
    origin = "https://app.example.test"
    redirect_uri = origin + "/callback"

    def request(method, path, browser=None, **options):
        send = requests.request if browser is None else browser.request
        return send(method, base + path, verify=certificate, timeout=10, allow_redirects=False, **options)

    for _ in range(100):
        try:
            master = request("POST", "/realms/master/protocol/openid-connect/token", data={
                "grant_type": "password", "client_id": "admin-cli",
                "username": "sso-admin", "password": admin_password,
            })
            if master.status_code == 200:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.5)
    else:
        raise AssertionError("Keycloak did not start or the bootstrap administrator was unavailable")

    admin_headers = {"Authorization": "Bearer " + master.json()["access_token"]}

    def admin(method, path, status, **options):
        return expect(request(method, path, headers=admin_headers, **options), status)

    admin("POST", "/admin/realms", 201, json={"realm": "sso-it", "enabled": True, "sslRequired": "all"})
    for client_id, allowed in ((client, "true"), (other_client, "false")):
        admin("POST", admin_realm + "/clients", 201, json={
            "clientId": client_id, "enabled": True, "protocol": "openid-connect", "secret": secret,
            "clientAuthenticatorType": "client-secret", "publicClient": False, "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True, "serviceAccountsEnabled": True, "redirectUris": [redirect_uri],
            "webOrigins": [origin], "attributes": {"browser-session.enabled": allowed},
        })
    user = admin("POST", admin_realm + "/users", 201, json={
        "username": "sso-user", "enabled": True, "firstName": "Sso", "lastName": "Test", "email": "sso@example.test",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    user_path = admin_realm + "/users/" + user.headers["Location"].rsplit("/", 1)[-1]

    def issue(client_id=client, grant_type="password", headers=None, **fields):
        form = {"grant_type": grant_type, "client_id": client_id, "client_secret": secret, **fields}
        if grant_type == "password":
            form.update(username="sso-user", password=password, scope="openid")
        return expect(request("POST", oidc + "/token", data=form, headers=headers), 200).json()

    def init(token, *, client_id=client, token_type="Bearer", auth="post", key=None, **fields):
        form = {"token": token, "token_type": token_type, "state": state}
        headers = {}
        if auth in ("basic", "mixed"):
            basic = quote_plus(client_id) + ":" + quote_plus(secret)
            headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
        if auth in ("post", "mixed"):
            form.update(client_id=client_id, client_secret=secret)
        form.update(fields)
        if key is not None:
            headers["DPoP"] = proof(key, "POST", base + init_path, token)
        return request("POST", init_path, data=form, headers=headers)

    def exchange(token, grant, *, token_type="Bearer", method="GET", browser=None, headers=None, **query):
        authorization = {"Authorization": f"{token_type} {token}", **(headers or {})}
        parameters = {"state": grant["state"], "challenge": grant["challenge"], **query}
        return request(method, challenge_path, browser=browser, headers=authorization, params=parameters)

    def authorize(browser, headers=None):
        redirect = expect(request("GET", oidc + "/auth", browser=browser, params={
            "client_id": client, "response_type": "code", "scope": "openid", "prompt": "none",
            "redirect_uri": redirect_uri, "state": state,
        }), 302)
        code = parse_qs(urlparse(redirect.headers["Location"]).query)["code"][0]
        return issue(grant_type="authorization_code", headers=headers, code=code, redirect_uri=redirect_uri)

    original = issue()
    token = original["access_token"]
    other_token = issue(other_client)["access_token"]
    expect(init(token, auth="mixed"), 400, "invalid_request")
    expect(init(token, client_secret="wrong"), 401, "invalid_client")
    expect(init(other_token, client_id=other_client), 403, "unauthorized_client")
    expect(init(other_token), 401, "invalid_token")
    expect(init(issue(grant_type="client_credentials")["access_token"]), 401, "invalid_token")
    expect(init(original["refresh_token"]), 401, "invalid_token")

    expiring_grant = expect(init(token), 200).json()
    assert expiring_grant["expires_in"] == 10
    expiry = time.monotonic() + expiring_grant["expires_in"]
    initial = expect(init(token, auth="basic"), 200)
    assert initial.headers["Cache-Control"] == "no-store"
    grant = initial.json()
    assert grant["state"] == state
    expect(exchange(token, grant, method="HEAD"), 405)
    expect(exchange(token, grant, state="other"), 400, "invalid_grant")
    expect(exchange(issue()["access_token"], grant), 400, "invalid_grant")
    expect(exchange(token, grant, headers={"Origin": "https://other.example.test"}), 403, "access_denied")
    preflight = expect(request("OPTIONS", challenge_path, headers={
        "Origin": origin, "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization,dpop,x-requested-with",
    }), 200)
    assert preflight.headers["Access-Control-Allow-Origin"] == origin
    assert {"authorization", "dpop", "x-requested-with"} <= {
        header.strip().lower() for header in preflight.headers["Access-Control-Allow-Headers"].split(",")
    }

    signer = ec.generate_private_key(ec.SECP256R1())
    with requests.Session() as browser:
        sso = expect(exchange(token, grant, browser=browser, headers={"Origin": origin}), 200)
        assert sso.headers["Access-Control-Allow-Origin"] == origin
        assert sso.headers["Access-Control-Allow-Credentials"] == "true"
        cookie = sso.cookies["KC_SSO_SESSION"]
        assert "KEYCLOAK_IDENTITY" in sso.cookies and "KEYCLOAK_SESSION" in sso.cookies
        assert session_id(authorize(browser)) == cookie != session_id(original)
        dpop = authorize(browser, headers={"DPoP": proof(signer, "POST", base + oidc + "/token")})
    expect(exchange(token, grant), 400, "invalid_grant")

    race = expect(init(token), 200).json()
    with ThreadPoolExecutor(max_workers=8) as workers:
        statuses = list(workers.map(lambda _: exchange(token, race).status_code, range(8)))
    assert sorted(statuses) == [200] + [400] * 7

    assert dpop["token_type"] == "DPoP"
    bound_token = dpop["access_token"]
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    expect(init(bound_token), 401, "invalid_token")
    expect(init(bound_token, token_type="DPoP"), 401, "invalid_token")
    expect(init(bound_token, token_type="DPoP", key=wrong_key), 401, "invalid_token")
    bound_grant = expect(init(bound_token, token_type="DPOP", key=signer), 200).json()
    expect(exchange(bound_token, bound_grant), 400, "invalid_grant")
    expect(exchange(bound_token, bound_grant, token_type="DPoP"), 401, "invalid_token")
    expect(exchange(bound_token, bound_grant, token_type="DPoP", headers={
        "DPoP": proof(signer, "GET", base + challenge_path, token),
    }), 401, "invalid_token")
    fresh = {"DPoP": proof(signer, "GET", base + challenge_path, bound_token)}
    result = expect(exchange(bound_token, bound_grant, token_type="DPoP", headers=fresh), 200)
    assert result.cookies["KC_SSO_SESSION"]
    bound_grant = expect(init(bound_token, token_type="DPoP", key=signer), 200).json()
    expect(exchange(bound_token, bound_grant, token_type="DPoP", headers=fresh), 401, "invalid_token")

    time.sleep(max(0, expiry - time.monotonic()))
    expect(exchange(token, expiring_grant), 400, "invalid_grant")
    stale_token = issue()["access_token"]
    stale = expect(init(stale_token), 200).json()
    admin("POST", user_path + "/logout", 204)
    expect(exchange(stale_token, stale), 401, "invalid_token")
    expect(init(stale_token), 401, "invalid_token")


def run(distribution, artifact, scratch):
    server = scratch / "keycloak"
    for directory in ("bin", "lib", "conf"):
        shutil.copytree(distribution / directory, server / directory)
    providers = server / "providers"
    providers.mkdir()
    shutil.copy2(artifact, providers / artifact.name)
    launch = [str(server / "bin" / "kc.sh")]
    env = {name: value for name, value in os.environ.items() if not name.startswith(("KC_", "KEYCLOAK_"))}
    output = subprocess.check_output(launch + ["--version"], env=env, text=True, timeout=30)
    version = re.search(r"(?m)^Keycloak (\d+\.\d+\.\d+)\b", output)[1]

    keytool = str(Path(os.environ["JAVA_HOME"]) / "bin" / "keytool") if "JAVA_HOME" in os.environ else "keytool"
    keystore = scratch / "localhost.p12"
    certificate = scratch / "localhost.pem"
    subprocess.run([keytool, "-genkeypair", "-alias", "localhost", "-keyalg", "RSA", "-keysize", "2048",
                    "-dname", "CN=localhost", "-ext", "SAN=DNS:localhost", "-validity", "1", "-storetype", "PKCS12",
                    "-keystore", str(keystore), "-storepass", "changeit"], check=True, timeout=20, capture_output=True)
    subprocess.run([keytool, "-exportcert", "-rfc", "-alias", "localhost", "-keystore", str(keystore),
                    "-storepass", "changeit", "-file", str(certificate)], check=True, timeout=20, capture_output=True)
    with socket.socket() as listener, socket.socket() as management:
        listener.bind(("127.0.0.1", 0))
        management.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        management_port = management.getsockname()[1]

    major = int(version.split(".")[0])
    admin_password = secrets.token_urlsafe()
    env["KC_CACHE"] = "local"
    if major >= 25:
        env["KC_HTTP_MANAGEMENT_PORT"] = str(management_port)
    if major >= 26:
        env.update(KC_BOOTSTRAP_ADMIN_USERNAME="sso-admin", KC_BOOTSTRAP_ADMIN_PASSWORD=admin_password)
    else:
        env.update(KEYCLOAK_ADMIN="sso-admin", KEYCLOAK_ADMIN_PASSWORD=admin_password)
    with (scratch / "keycloak.log").open("w+") as log:
        try:
            subprocess.run(launch + ["build", "--db=dev-mem", "--features=dpop"], env=env,
                           stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
            process = subprocess.Popen(launch + [
                "start", "--optimized", "--hostname-strict=false", "--http-host=127.0.0.1",
                f"--https-port={port}", f"--https-key-store-file={keystore}", "--https-key-store-password=changeit",
                "--spi-realm-restapi-extension-sso-challenge-ttl=10",
            ], env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                check_sso(f"https://localhost:{port}", str(certificate), admin_password)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        except Exception:
            log.seek(0)
            print(log.read())
            raise
    print(f"Keycloak {version}: client authentication, browser SSO, CORS, DPoP, replay, TTL and logout passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SSO compatibility checks on a temporary local Keycloak server")
    parser.add_argument("distribution", type=Path, help="path to an unpacked Keycloak distribution")
    parser.add_argument("artifact", type=Path, help="path to the built browser-session SPI JAR")
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="browser-session-compat-") as directory:
        run(arguments.distribution.resolve(), arguments.artifact.resolve(), Path(directory))
