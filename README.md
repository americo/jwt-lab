# JWT Algorithm "none" Vulnerability Demo

This is a simple Node.js application that demonstrates a JWT vulnerability related to the "none" algorithm. This application is intentionally vulnerable for educational purposes only.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

## Testing the Vulnerability

### 1. Get a Valid Token
First, get a valid JWT token by logging in:
```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 2. Exploit the Vulnerability
The application is vulnerable to the "none" algorithm attack. Here's how to exploit it:

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

## Security Implications

This vulnerability occurs because:
1. The application accepts tokens with the "none" algorithm
2. The verification process doesn't properly validate the algorithm
3. Tokens without a signature are accepted

## How to Fix

To fix this vulnerability:
1. Always specify the exact algorithm to use during verification
2. Never accept tokens with the "none" algorithm
3. Always verify the signature

Example of secure verification:
```javascript
jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
``` 