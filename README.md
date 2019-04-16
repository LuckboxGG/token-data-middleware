# token-data-middleware
Validates and extracts data from signed tokens

## Examples

### Express 4.x middleware

```js
const express = require('express');
const fs = require('fs');

const app = express();

const { tokenData } = require('@luckbox/token-data-middleware');
const publicKey = fs.readFileSync('id_ecdsa.pub.pem');

app.use(tokenData(publicKey, 'Custom-Token-Header'));

app.post('/message', (req, res) => {
  if (!req.tokenData.id) {
    return res.status(403).send('Permission denied');
  }

  // new message logic goes here...
});

app.listen(80);
```

### Manual usage

```js
const fs = require('fs');

const { parser } = require('@luckbox/token-data-middleware');
const publicKey = fs.readFileSync('id_ecdsa.pub.pem');

const tokenParser = parser(publicKey);

const token = 'qZPb3DyNIOnTeRv4oSy5TraslRO41AYjDlxSttpW5PWIcKIwqvlGDgMWPjhbIKpdcoX6mfsG9dwC-JRz5wbVAgeyJpZCI6MTIzNDV9';

const tokenData = tokenParser(token);
console.log(tokenData); // { id: 12345 }
```

## API

### Methods

#### `module#parser(publicKey) : tokenParser()`

Initializes a new token parser.

Name      | Type            | Description
----------|-----------------|------------
publicKey | `String|Buffer` | PEM-formatted public key

#### `module#tokenData(publicKey[, headerName]) : ExpressMiddleware`

Creates a new Express 4.x middleware.

Name       | Type            | Default | Description
-----------|-----------------|---------|------------
publicKey  | `String|Buffer` |         | PEM-formatted public key
headerName | `String`        | "Token" | An optional name for the header from which to extract the token data

#### `sign(payload, privateKey) : Object`

Signs a payload and generates a token provided an ECDSA private key.

Name       | Type     | Description
-----------|----------|------------
payload    | any      | Payload to sign
privateKey | `String` | PEM-formatted private key


#### `tokenParser(token) : Object`

Parses a signed token and returns the data contained within. In case the token is invalid, an empty object is returned.

Name      | Type     | Description
----------|----------|------------
publicKey | `String` | PEM-formatted public key
