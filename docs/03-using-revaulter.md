# Using Revaulter

Revaulter can be used to perform six different cryptographic operations using keys stored on Azure Key Vault: encrypting and decrypting messages, wrapping and unwrapping keys, and computing and verifying digital signatures.

## Flow

Regardless of the operation in use, the regular flow is the same:

1. The application that requires the operation makes an API call to a `POST /request/[operation]` endpoint (for example, `POST /request/wrapkey`), with the data (such as the key to wrap) in the body. The response contains a `state` ID.
2. The application invokes `GET /request/result/[state]` with the state ID. This request will block until the result is available.
3. Revaulter receives the request and sends a notification to an admin.
4. An admin visits the Revaulter page, authenticates with Azure AD, and then approves the operation. If the admin denies the operation, or the request expires, Revaulter removes the request from its state and the flow stops.
5. Once the request is approved, Revaulter performs the operation within the Key Vault.
6. Revaulter sends the result to the application by responding to the pending `GET /request/result/[state]` request. The response is sent only once.

Revaulter uses delegated permissions to access Azure Key Vault. It uses the access token the user provides after logging in with Azure AD to make requests to Azure Key Vault, with the access level granted to the user.

### Headless flow

In some cases, waiting for the user to visit the Revaulter page and authenticate with Azure AD is not possible. In this case, Revaulter can be used with the "headless flow", in which an access token with permissions to perform operations in the Azure Key Vault is passed directly in the request; this is an advanced scenario that is indicated in a limited number of cases.

If you already have an access token with permissions to access Azure Key Vault and perform operations there, you can pass it to the `POST /request/[operation]` endpoints in the `Authorization` header, as a Bearer token. For example:

```sh
curl https://10.20.30.40:8080/request/encrypt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbG..." \
  --data '...'
```

In this case, the flow does not require an admin's intervention:

1. The application that requires the operation makes an API call to a `POST /request/[operation]` endpoint (for example, `POST /request/wrapkey`), with the data (such as the key to wrap) in the body and the access token in the `Authorization` header, as a Bearer token. The response contains a `state` ID.
2. The application invokes `GET /request/result/[state]` with the state ID to retrieve the result. This value can only be retrieved once.

Obtaining is the access token for the "headless flow" is outside of the scope of Revaulter. Your application can obtain that in any way supported by Azure AD, including using the [client credentials flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow).

## APIs

Unlocker has 7 API endpoints, including one for each of the 6 supported operations and one to retrieve the result.

For `POST` requests, the data must be passed in the request body. Revaulter supports multiple formats, including:

- JSON-encoded bodies, with the `Content-Type: application/json` header
- Form-encoded bodies, with the `Content-Type: application/x-www-form-urlencoded` header

Many properties require data to be base64-encoded. Revaulter supports both base64 "standard" (RFC 4648 §4) and "URL-safe" (RFC 4648 §5) encodings, and padding is always optional.

> **Note:** in all the examples we're using the `--insecure` flag to tell curl to accept self-signed TLS certificates. If you are using a TLS certificate signed by a Certification Authority, you can (and should) omit that flag.

> Access to the `/request` endpoints can be limited to allowlisted IPs using the `allowedIps` configuration option (see [Configuration](02-install-and-configure-revaulter.md#configuration))

### `POST /request/encrypt`: Encrypt a message

This method creates a request to encrypt a message.

The request body contains the following properties:

- **`value`** (string, base64-encoded): The message to encrypt.
- **`algorithm`** (string): Algorithm to use to encrypt the message. The string is a constant defined by the JSON Web Encryption standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`vault`** (string): The name of the Azure Key Vault instance where the key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`nonce`** (string, base64-encoded): Nonce (or Initialization Vector) for the encryption operation. Although this field is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`additionalData`** (string, base64-encoded): Additional Authenticated Data for the encryption operation. Note that not all algorithms support this field.
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`timeout`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`note`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.

The response body contains the following properties:

- **`state`** (string): State ID, which can be used by the application to retrieve the result. See [`GET /request/result/[state]`](#get-requestresultstate-retrieve-the-result)
- **`pending`** (boolean): Always set to "true".

Example request, using curl:

```sh
curl https://10.20.30.40:8080/request/encrypt \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"mykey1","algorithm":"RSA-OAEP-256","value":"aGVsbG93b3JsZA==","timeout":"10m"}'
```

Example response:

```json
{
  "state": "be976f6c-ae1e-4425-9e9f-4db6871c1861",
  "pending": true
}
```

### `POST /request/decrypt`: Decrypt a message

This method creates a request to decrypt a message.

The request body contains the following properties:

- **`value`** (string, base64-encoded): The message to decrypt.
- **`algorithm`** (string): Algorithm to use to decrypt the message. The string is a constant defined by the JSON Web Encryption standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`vault`** (string): The name of the Azure Key Vault instance where the key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`nonce`** (string, base64-encoded): Nonce (or Initialization Vector) for the decryption operation. Although this field is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`tag`** (string, base64-encoded): Authentication tag for the decryption operation. Although this field is optional, it may be required by some algorithms (such as authenticated ciphers), and omitting that may cause Azure Key Vault to return an error.
  - **`additionalData`** (string, base64-encoded): Additional Authenticated Data for the decryption operation. Note that not all algorithms support this field.
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`timeout`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`note`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.

The response body contains the following properties:

- **`state`** (string): State ID, which can be used by the application to retrieve the result. See [`GET /request/result/[state]`](#get-requestresultstate-retrieve-the-result)
- **`pending`** (boolean): Always set to "true".

Example request, using curl:

```sh
curl https://10.20.30.40:8080/request/decrypt \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"mykey1","algorithm":"RSA-OAEP-256","value":"pftzpou...MlxVIk","timeout":"10m"}'
```

Example response:

```json
{
  "state": "a963f35b-65b6-42d5-8dd2-bdf04c98c7bb",
  "pending": true
}
```

### `POST /request/sign`: Sign a message

### `POST /request/verify`: Verify a digital signature

### `POST /request/wrapkey`: Wrap a key

This method creates a request to wrap a key.

The request body contains the following properties:

- **`value`** (string, base64-encoded): The key to wrap.
- **`algorithm`** (string): Algorithm to use to wrap the key. The string is a constant defined by the JSON Web Encryption standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`vault`** (string): The name of the Azure Key Vault instance where the key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`nonce`** (string, base64-encoded): Nonce (or Initialization Vector) for the wrapping operation. Although this field is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`additionalData`** (string, base64-encoded): Additional Authenticated Data for the wrapping operation. Note that not all algorithms support this field.
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`timeout`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`note`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.

The response body contains the following properties:

- **`state`** (string): State ID, which can be used by the application to retrieve the result. See [`GET /request/result/[state]`](#get-requestresultstate-retrieve-the-result)
- **`pending`** (boolean): Always set to "true".

Example request, using curl:

```sh
curl https://10.20.30.40:8080/request/wrapkey \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"mykey1","algorithm":"RSA-OAEP-256","value":"aGVsbG93b3JsZA==","timeout":"10m"}'
```

Example response:

```json
{
  "state": "8156ed14-b608-417c-a267-42bd3325871f",
  "pending": true
}
```

### `POST /request/unwrapkey`: Unwrap a key

This method creates a request to unwrap a key.

The request body contains the following properties:

- **`value`** (string, base64-encoded): The key to unwrap.
- **`algorithm`** (string): Algorithm to use to unwrap the key. The string is a constant defined by the JSON Web Encryption standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`vault`** (string): The name of the Azure Key Vault instance where the key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`nonce`** (string, base64-encoded): Nonce (or Initialization Vector) for the unwrapping operation. Although this field is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`tag`** (string, base64-encoded): Authentication tag for the unwrapping operation. Although this field is optional, it may be required by some algorithms (such as authenticated ciphers), and omitting that may cause Azure Key Vault to return an error.
  - **`additionalData`** (string, base64-encoded): Additional Authenticated Data for the unwrapping operation. Note that not all algorithms support this field.
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`timeout`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`note`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.

The response body contains the following properties:

- **`state`** (string): State ID, which can be used by the application to retrieve the result. See [`GET /request/result/[state]`](#get-requestresultstate-retrieve-the-result)
- **`pending`** (boolean): Always set to "true".

Example request, using curl:

```sh
curl https://10.20.30.40:8080/request/unwrapkey \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"mykey1","algorithm":"RSA-OAEP-256","value":"pftzpou...MlxVIk","timeout":"10m"}'
```

Example response:

```json
{
  "state": "0ebd5480-fc9e-43f0-b1bb-bf3017b7cc5e",
  "pending": true
}
```

### `GET /request/result/[state]`: Retrieve the result

This method is used to retrieve the result of an operation.

- If the operation is complete (approved, rejected, or expired), Revaulter returns the result of the operation right away.
  - For successful responses, the result is returned only once, to the first caller. After responding to an application, Revaulter deletes the result from its state.
- If the operation is pending, this request blocks until the operation is completed (approved, rejected, or expired).

## Example: wrap and unwrap a key

In this section we'll be looking at how to wrap and unwrap a key, which in our example is `helloworld`; Revaulter supports any kind of keys and keyfiles, for both symmetric and asymmetric ciphers.

We will use a key called `wrappingkey1` stored inside an Azure Key Vault called `myrevaulterkv`. We also assume that Revaulter is available at the address `https://10.20.30.40:8080`.

## APIs

There are two main API endpoints you and your application will interact with:

- First, you wrap your keys using the `/wrap` endpoint (see [Wrapping a key](#wrapping-a-key)). This needs to be done just once for each key. You will receive a wrapped (ie. encrypted) key that you can safely store alongside your application.
- Every time your application needs to retrieve the key (usually when the application starts), it should make a call to the `/unwrap` endpoint (see [Unwrapping a key](#unwrapping-a-key)).

Both the `/wrap` and `/unwrap` endpoints return a unique operation ID ("state") that your application can then use with the `/result` endpoint to retrieve the wrapped or unwrapped key after an admin approved the request. Read below for details on how it works.

### Wrapping a key

To wrap (encrypt) a key, first make a POST request to the **`/wrap`** endpoint. The POST request's body must be a JSON document containing the following keys:

- **`value`** (string, base64-encoded): This is the key that you want to wrap. It must be encoded as base64 (Revaulter supports both base64 standard and URL-safe encoding, and padding is optional).
- **`vault`** (string): The name of the Azure Key Vault where the wrapping key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest key.
  - **`timeout`** (integer): An optional timeout for the operation, in seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 300 seconds, or 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`note`** (string): A freeform message that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.

For example, with curl and the sample data above (note that `aGVsbG93b3JsZA==` is the base64-encoded representation of `helloworld`, the key we want to encrypt; we are also setting an optional timeout of 10 minutes, or 600 seconds):

```sh
curl https://10.20.30.40:8080/wrap \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"aGVsbG93b3JsZA==","timeout":600,"note":"The secret"}'
```

> Note: in all the examples we're using the `--insecure` flag to tell curl to accept self-signed TLS certificates. If you are using a TLS certificate signed by a Certification Authority, you can (and should) omit that flag.

The response will be a JSON object similar to this, where `state` is the ID of the request.

```json
{
  "state": "4336d140-2ba1-4d7a-af84-a83d564e384b",
  "pending": true
}
```

At this point the administrator should receive a notification through the webhook configured in the app. The notification contains a link they can click on to confirm or deny the operation; if they don't take action before the timeout, the request is automatically canceled. The administrator will need to authenticate with their Azure AD account that has permission to use the key in the Key Vault, and then will have to confirm the operation.

Your application can obtain the key by making a GET request to the `/result/:state` endpoint, such as:

```sh
STATE_ID="4336d140-2ba1-4d7a-af84-a83d564e384b"
curl --insecure https://10.20.30.40:8080/result/${STATE_ID}
```

> You can automatically set the value of the `STATE_ID` variable from the `/wrap` request using jq:
>
> ```sh
> STATE_ID=$(\
>   curl https://10.20.30.40:8080/wrap \
>     --insecure \
>     -H "Content-Type: application/json" \
>     --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"aGVsbG93b3JsZA==","timeout":600}' \
>   | jq -r .state
> )
> ```

The request to the `/result/:state` endpoint will hang until the operation is complete. Note that your client (or any network or proxy you're connecting through) may make the request time out before you can get the result. In this case, it's safe to re-invoke the request until you get status code of 200 (the response contains your wrapped key) or 400-499 (a 4xx status code happens when the request was denied or expired). Note that once you retrieve the response, the request and its result are removed from Revaulter and you won't be able to retrieve them again (unless you start a new request and get that approved again).

A **successful**, final response will contain a JSON body similar to:

```json
{
  "state": "a6dfdcea-3330-4f55-91f7-2ec9ea02370a",
  "done": true,
  "value": "pftzpouF10Dvg1dFcHuxk1sHr3dVauTydCyJS4NRl2rQrWK6ZpGgZCIArX+svYaYo3vYYqvxGzJIeqDTCr11fM4HbqgHO/W9HR8lQZKsIbeyfq1gLQ3sBGrpTwa5HABU889387AjXDshhEHI6L9D7JHBzKE1+eXWhQL9RtxbnfsHTQ49nCS5AXLetzDuwJRxWSZzTqNu8XILsEv91y41jtc8LOxOpDudc3tRJ6KNNNxCsehnuzBmZPqh/OhAH8AHZz1gESQGhRQKiZVgobLT7uzGlv0zPqTU2jbp1swF7apADnjdcUl93nYeBaOH3KqXs1PK12C14fV6qfwTMTsQTRM6OFB2FYTGeGoq5Gfo8FtnK7/oIIDtqo2RaK+83SexM1Fe3GNw7dU3zckGCpVjzLtHJZiYcP5VnybmFPmFV1RrsEnR4aMAigFkFEE/oZcsS8ZDwtwRPGGUEoCpZw8vqCzk1/2rtHmwkcSRCuoGR0s2yR9t889hc3C5r490zP+qGZ7fh/jBizXvJMCYjYA4z/A5LXOTENGEq3Mq0SWlh6+zxaP95+sKho7P3pHsIf9mK6VLWm2jhbWADx9R59DIoP6nKRtYivEk7UoI7tV9N7krgD1sMzK/Kk4YXu7mETAQR8o77Vo5dX+UJgF+jsNPrkG16x8TInKCeDYawMlxVIk="
}
```

The `value` field contains the wrapped key, encoded using base64 "standard encoding" with padding included (per [RFC 4648 section 4](https://datatracker.ietf.org/doc/html/rfc4648#section-4)).

The `/result/:state` endpoint accepts an optional `?raw=1` parameter that makes the response contain the (wrapped) key only, as binary data. For example:

```sh
STATE_ID="4336d140-2ba1-4d7a-af84-a83d564e384b"
curl --insecure "https://10.20.30.40:8080/result/${STATE_ID}?raw=1"
# A successful response will contain binary data
```

Because this value is wrapped, so encrypted, it's safe to store it on your server, next to the application that needs it. When you need the original key (`helloworld`) you can then use the `/unwrap` method to have the key unwrapped as we'll see in the next section.

### Unwrapping a key

The process for unwrapping a key is similar to the one for wrapping a key presented in the previous section. Unwrapping a key means retrieving the original, plain-text key, letting Azure Key Vault perform the unwrapping (decryption) using the RSA key stored in the vault.

To unwrap a key, first make a POST request to the **`/unwrap`** endpoint. The POST request's body must be a JSON document containing the following keys (same as in the `/wrap` request, but the value is the wrapped key):

- **`value`** (string, base64-encoded): This is the wrapped key, encoded as base64 (Revaulter supports both base64 standard and URL-safe encoding, and padding is optional).
- **`vault`** (string): The name of the Azure Key Vault where the wrapping key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest key.
  - **`timeout`** (integer): An optional timeout for the operation, in seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 300 seconds, or 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.

For example, to unwrap the key wrapped above with curl, we can make this request (note that the `value` field contains the key that was wrapped earlier, partially omitted here for legibility):

```sh
curl https://10.20.30.40:8080/unwrap \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"pftzpou...MlxVIk="}'
```

The response will be a JSON object similar to this, where `state` is the ID of the request.

```json
{
  "state": "4336d140-2ba1-4d7a-af84-a83d564e384b",
  "pending": true
}
```

The rest of the process is identical to the one you followed to wrap a key.

> Just as above, you can pipe the curl request to jq to get the state in a `STATE_ID` variable automatically:
>
> ```sh
> STATE_ID=$(\
>   curl https://10.20.30.40:8080/unwrap \
>     --insecure \
>     -H "Content-Type: application/json" \
>     --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"pftzpou...MlxVIk="}' \
>   | jq -r .state
> )
> ```

The administrator will receive another notification through the webhook configured in the app. They will be asked to sign in with their Azure AD account and confirm or deny the operation before it times out.

Just as when wrapping a key, your application can invoke the `/result/:state` method to check the status of the request. This will block until the operation is complete, and the result will contain the unwrapped key (base64-encoded):

```sh
curl --insecure https://10.20.30.40:8080/result/${STATE_ID}
```

A **successful**, final response will contain a JSON body similar to:

```json
{
  "state": "a6dfdcea-3330-4f55-91f7-2ec9ea02370a",
  "done": true,
  "value": "aGVsbG93b3JsZA=="
}
```

You can notice that the `value` field contains the plain-text key encoded as base64 (standard encoding, with padding). `aGVsbG93b3JsZA==` is the base64-encoded representation of `helloworld`, our example key.

Just as before, note that requests to `/result/:state` may time out because of your client or the network. If your request times out, you should make another request to `/result/:state` until you get a 200 status code (success) or 400-499 status code (an error, such as request denied or expired). Note that once you retrieve the response, the request and its result are removed from Revaulter and you won't be able to retrieve them again (unless you start a new request and get that approved again).

Using curl and jq, you can retrieve the raw (decoded) key to pipe it directly to an application that needs to consume it with:

```sh
curl --insecure https://10.20.30.40:8080/result/${STATE_ID} \
  | jq -r .value \
  | base64 --decode
```

The command above will print the unwrapped key (in our case `helloworld`), in plain text. You can redirect that to a file (adding `> file-name`) or to another app (with a pipe `|`).

Alternatively, the `/result/:state` endpoint accepts an optional `?raw=1` parameter that makes the response contain the unwrapped key only, as binary data. For example:

```sh
curl --insecure "https://10.20.30.40:8080/result/${STATE_ID}?raw=1"
# A successful response will contain binary data; in our example that would be "helloworld"
```

### Supported algorithms and keys

Revaulter can wrap and unwrap data using keys stored in Azure Key Vault only, either software-protected or HSM-protected.

Revaulter only supports RSA keys. Although all key sizes supported by Azure Key Vault can be used with Revaulter, we strongly recommend using 4096-bit keys for the best security.

Revaulter uses RSA-OAEP with SHA-256 (identified as `RSA-OAEP-256` in Azure Key Vault) as algorithm and mode of operation, to offer the best security. This value is not configurable.
