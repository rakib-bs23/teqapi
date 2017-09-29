from django.http import JsonResponse
from jose import jwt

AUTH0_DOMAIN = 'teq.auth0.com'
API_AUDIENCE = 'https://teq.auth0.com/api/v2/'
ALGORITHMS = ["RS256"]
AUTH0_PUBLIC_KEY = {"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["MIIC9TCCAd2gAwIBAgIJCV1E4DdKpSsyMA0GCSqGSIb3DQEBCwUAMBgxFjAUBgNVBAMTDXRlcS5hdXRoMC5jb20wHhcNMTcwOTI5MDYzNTIxWhcNMzEwNjA4MDYzNTIxWjAYMRYwFAYDVQQDEw10ZXEuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhQKNZU2+R/yZQsLkHzw/kWN5AOKg3W7jx4LJmjG5z9C8phqcq6x2Z+KjgSMSAVYH7VoBIHtY8QMTa5nzsEgZCqG8xZ5oKuWcKX+OiegGmqkXQiQMbsMwS7L8diw36CjIbCBTrXD+mziN0VV3m2xI7HxkSHStTRRFaHP6KCCQbwvS8pa+WNPvcD1R6d9j65A8K/rPoDKMHHBf9Pim36PU66rBa7VG/pr5cPUGx1NQeCrbi84lmi/WMZkAkh4dPZK195OSLxxaia7iYUJIpuYgsh4b9ady9xlRKLKWZfXn5++HUvGltolgaDNi6ra5wZ9NWTYpHjiw54N4cT35SQn2wIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSgx1FLmCqt3RmRdrWwDZuiB95SBDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBACfkh9G+BQBtatY+0/7K6ZWAXEiXcEKJMZ0JHD/K3Ov/aRW+idIB7+zah/h7LwThNcHMkOXdbUgJlTY+ZL2CMkoNKKKRb2apwBcrw+1qvX+44wc6rB7Dr498BcDjajy0gSDLNYLxPUlzM+0dRErn0Q8+2bR9LWU2bdSPuMBrMeN29n8UXyUm3hdvwoMiVDwzJPYufAtV4Tv82XriyEEtoDn/qdJUPplQitejNB5hj9V4ViIR2DHl+DqVlwuY3VLwjvq3Q9omGTZwEy7zUEzB3nMnwW1xi80HqPtv20IYNEZXOpgeNxivz7LfUC7fjNqj2In+w9BIzK46wPA3JkQznQU="],"n":"rhQKNZU2-R_yZQsLkHzw_kWN5AOKg3W7jx4LJmjG5z9C8phqcq6x2Z-KjgSMSAVYH7VoBIHtY8QMTa5nzsEgZCqG8xZ5oKuWcKX-OiegGmqkXQiQMbsMwS7L8diw36CjIbCBTrXD-mziN0VV3m2xI7HxkSHStTRRFaHP6KCCQbwvS8pa-WNPvcD1R6d9j65A8K_rPoDKMHHBf9Pim36PU66rBa7VG_pr5cPUGx1NQeCrbi84lmi_WMZkAkh4dPZK195OSLxxaia7iYUJIpuYgsh4b9ady9xlRKLKWZfXn5--HUvGltolgaDNi6ra5wZ9NWTYpHjiw54N4cT35SQn2w","e":"AQAB","kid":"RDUyN0YyN0ExRjYxQkMyMEZCNzBBRTM5QTI2NzhFOTQ2MzlFMUJDOQ","x5t":"RDUyN0YyN0ExRjYxQkMyMEZCNzBBRTM5QTI2NzhFOTQ2MzlFMUJDOQ"}]}

class Auth0Middleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # IF URL CONTAINS api
        # if (request.path).split('/')[1] == 'api':
            # GET TOKEN
        auth = request.META.get('HTTP_AUTHORIZATION')
        if not auth:
            return JsonResponse(data={"code": "authorization_header_missing",
                                      "description":
                                          "Authorization header is expected"}, status=401)
        parts = auth.split()
        if parts[0].lower() != "bearer":
            return JsonResponse(data={"code": "invalid_header",
                                      "description":
                                          "Authorization header must start with"
                                          "Bearer"}, status=401)
        elif len(parts) == 1:
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Token not found"}, status=401)
        elif len(parts) > 2:
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Authorization header must be"
                                                     "Bearer token"}, status=401)
        token = parts[1]

        # VALIDATE TOKEN
        jwks = AUTH0_PUBLIC_KEY
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Invalid header. "
                                                     "Use an RS256 signed JWT Access Token"}, status=401)
        if unverified_header["alg"] == "HS256":
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Invalid header. "
                                                     "Use an RS256 signed JWT Access Token"}, status=401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except jwt.ExpiredSignatureError:
                return JsonResponse(data={"code": "token_expired",
                                          "description": "token is expired"}, status=401)
            except jwt.JWTClaimsError:
                return JsonResponse(data={"code": "invalid_claims",
                                          "description": "incorrect claims,"
                                                         " please check the audience and issuer"}, status=401)
            except Exception:
                return JsonResponse(data={"code": "invalid_header",
                                          "description": "Unable to parse authentication"
                                                         " token."}, status=400)
        else:
            return JsonResponse(data={"code": "invalid_header",
                                      "description": "Unable to find appropriate key"}, status=401)

        response = self.get_response(request)
        return response