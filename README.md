# JWT Interface Library

A lightweight Python library for generating, validating, and extracting JSON Web Tokens (JWT) with JWS (JSON Web Signature) support.

## Features
- Generate JWS Tokens: Create secure tokens with customizable headers.
- Validate Tokens: Check token authenticity with HS256/HS512 algorithms.
- Extract Payloads: Retrieve payload data from valid tokens.
- Custom Exceptions: Handle errors like invalid tokens or headers.

## Installation
Clone the repository:
```bash
git clone https://github.com/sepehrtdarvish/python-jwt-kit.git
```

## Usage
### Initialize the Interface
```python
from core.jws_core import JWTInterface
jwt_interface = JWTInterface(token_type="jws")
```

### Generate Token
```python
payload = {"user_id": 123}
secret = "my_secret_key"
token = jwt_interface.generate_token(payload, secret)
print(token)
```

### Validate Token
```python
is_valid = jwt_interface.is_token_valid(token, secret)
print(is_valid)  # True or False
```

### Extract Payload
```python
payload = jwt_interface.extract_token(token, secret)
print(payload)
```

## Exceptions
| Exception                     | Description                                |
|-------------------------------|--------------------------------------------|
| `InvalidInterfaceName`        | Unsupported token type.                   |
| `InvalidToken`                | Token validation failed.                  |
| `TokenTypeNotFound`           | Missing `typ` field in the header.        |
| `TokenSignAlgorithmNotFound`  | Missing `alg` field in the header.        |

## Run Tests
Run the unit tests:
```bash
python -m unittest discover tests
```


