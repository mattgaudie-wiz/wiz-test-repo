import json
import base64
import hmac
import hashlib

jwt_header = """
{
  "alg": "HS256",
  "typ": "JWT"
}
"""

jwt_data = """
{
  "sub": "cd08769d-c6a5-43cf-be5f-14f34ecddaa2",
  "name": "Your Friendly Neighbor",
  "iat": 1609459200
}
"""

jwt_values = {
  "header": jwt_header,
  "data": jwt_data,
}

# remove all the empty spaces
jwt_values_cleaned = {
  key: json.dumps(
    json.loads(value),
    separators = (",", ":"),
  ) for key, value in jwt_values.items()
}

jwt_values_enc = {
  key: base64.urlsafe_b64encode(
      value.encode(encoding)
    ).decode(encoding).rstrip('=') for key, value in jwt_values_cleaned.items()
}

sig_payload = "{header}.{data}".format(
  header = jwt_values_enc['header'],
  data = jwt_values_enc['data'],
)

secret_key = b"your-secret-goes-here"

sig = hmac.new(
  secret_key,
  msg = sig_payload.encode(encoding),
  digestmod = hashlib.sha256
).digest()

ecoded_sig = base64.urlsafe_b64encode(sig).decode(encoding).rstrip("=")

jwt_token = "{sig_payload}.{sig}".format(
  sig_payload = sig_payload,
  sig = ecoded_sig
)
