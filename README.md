# Encrypted API - PHP client
Use this client in any PHP application to call any Encrypted API endpoint.

# Installation
```
composer require kbs1/encrypted-api-client-php
```
The package is now installed.

# Operation
This client encrypts and hides the following data before calling the Encrypted API service: `headers` (including cookies), `request data`.
Query string, location URI, HTTP verb are transmited as-is.

# Usage
Calling encrypted API service can be accomplished in the following way:
```
$call = new \Kbs1\EncryptedApi\Http\ApiCall("https://server-application.dev/api/$ourUuid/users/disable", 'POST', [
	'user_uuid' => '...',
	'parameter1' => true,
	'parameter2' => 'foo',
	...
], $secret1, $secret2);

try {
	$response = $call->execute(); // will execute the call each time invoked
} catch (\Kbs1\EncryptedApi\Exceptions\EncryptedApiException $ex) {
	...
}

// retrieve service response later if desired
$response = $call->response();
$http_status_code = $call->httpStatus();
$response_headers = $call->headers();
```
`$response` will contain any response sent by the service. This might be JSON or any other service response you implement. All service responses protected
by this package are always properly signed and encrypted before sending, even if an exception occurs (invalid request data, crashes in your service
and so on). This means no one, without knowing the required shared secrets, is able to read the service response in any case.

`ApiCall` constructor can take either collection or array as the third optional data argument.
Fourth and fifth arguments (`secret1` and `secret2`) are optional as well and if they are omitted, shared secrets are loaded
from `config/encrypted_api.php` file.

For `GET` requests, the package will send a request body as well. This ensures the request must also be properly signed, and no one except the authorised
caller can call the route.

### A note on query string and route parameters
It is adivsed to send each API service parameter using third (data) argument of the `ApiCall` class only (even for GET requests).
Althrough the package verifies the exact URL that was called (including query string and HTTP method) on the server side, sensitive data passed as
query parameters or route segments can still be captured for example in server's access log.

Securely passed parameters (third data argument) always overwrite query string paramets, using Laravel's `$request->merge()` method.

The only parameter that is advised to be passed as query string parameter or route segment is the `clientUuid` parameter, should you have multiple calling
clients. As this parameter is used to load shared secrets for particular client, it can not be passed encrypted.
