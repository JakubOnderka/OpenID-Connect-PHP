# PHP OpenID Connect Basic Client

[![Latest Stable Version](http://poser.pugx.org/jakub-onderka/openid-connect-php/v)](https://packagist.org/packages/jakub-onderka/openid-connect-php) [![Latest Unstable Version](http://poser.pugx.org/jakub-onderka/openid-connect-php/v/unstable)](https://packagist.org/packages/jakub-onderka/openid-connect-php) [![PHP Version Require](http://poser.pugx.org/jakub-onderka/openid-connect-php/require/php)](https://packagist.org/packages/jakub-onderka/openid-connect-php)

A simple library that allows an application to authenticate a user through the basic OpenID Connect flow.
This library hopes to encourage OpenID Connect use by making it simple enough for a developer with little knowledge of
the OpenID Connect protocol to setup authentication.

**This is a fork of [jumbojett/OpenID-Connect-PHP](https://github.com/jumbojett/OpenID-Connect-PHP)**

Jumbojett`s library is great, but lacks of some features, proper testing, and it is not ready for new PHP versions. So I created
this fork. This fork requires PHP 7.1 or greater, if you need to use older PHP version, please use original version.

**Most important changes:**

* Added support for elliptic curve (EC) JWT token signature algorithms, that are faster than RSA signatures
* Added support for `client_secret_jwt` and `private_key_jwt` authentication methods to token endpoint, that are more secure that traditional method
* JWT ID Token Validation compliant to OpenID Connect standard
* Much higher code coverage by unit tests
* A lot of small optimisations and fixes

A special thanks goes to Michael Jett, original author of this library and Justin Richer and Amanda Anganes for their help and support of the protocol.

## Requirements

 1. PHP 7.1 or greater
 2. CURL extension
 3. JSON extension
 4. APCu for caching (optional)

## Install
 1. Install library using composer
```
composer require jakub-onderka/openid-connect-php
```
 2. Include composer autoloader
```php
require __DIR__ . '/vendor/autoload.php';
```

## Example 1: Basic Client

```php
use JakubOnderka\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://id.provider.com', 'ClientIDHere', 'ClientSecretHere');
$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
```

[See openid spec for available user attributes][1]

## Example 2: Dynamic Registration

```php
use JakubOnderka\OpenIDConnectClient;

$oidc = new OpenIDConnectClient("https://id.provider.com");

$response = $oidc->register("Client Name");
$clientID = $response->client_id;
$clientSecret = $response->client_secret;

// Be sure to add logic to store the client id and client secret
```

## Example 3: Network and Security

```php
// Configure a proxy
$oidc->setHttpProxy("http://my.proxy.com:80/");

// Configure a cert
$oidc->setCertPath("/path/to/my.cert");
```

## Example 4: Request Client Credentials Token

```php
use JakubOnderka\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://id.provider.com', 'ClientIDHere', 'ClientSecretHere');
$oidc->providerConfigParam(['token_endpoint' => 'https://id.provider.com/connect/token']);
$oidc->addScope('my_scope');

// This assumes success (to validate check if the access_token property is there and a valid JWT):
$clientCredentialsToken = $oidc->requestClientCredentialsToken()->access_token;
```

## Example 5: Request Resource Owners Token (with client auth)

```php
use JakubOnderka\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://id.provider.com', 'ClientIDHere','ClientSecretHere');
$oidc->providerConfigParam(['token_endpoint' => 'https://id.provider.com/connect/token']);
$oidc->addScope('my_scope');

// Add username and password
$oidc->addAuthParam([
  'username' => '<Username>',
  'password' => '<Password>',
]);

// Perform the auth and return the token (to validate check if the access_token property is there and a valid JWT):
$token = $oidc->requestResourceOwnerToken(true)->access_token;
```

## Example 6: Basic client for implicit flow e.g. with Azure AD B2C

See https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth

```php
use JakubOnderka\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://id.provider.com', 'ClientIDHere', 'ClientSecretHere');
$oidc->setResponseTypes(['id_token']);
$oidc->addScope(['openid']);
$oidc->setAllowImplicitFlow(true);
$oidc->addAuthParam(['response_mode' => 'form_post']);
$oidc->setCertPath('/path/to/my.cert');
$oidc->authenticate();
$sub = $oidc->getVerifiedClaims('sub');
```

## Example 7: Introspection of access token

See https://tools.ietf.org/html/rfc7662

```php
use JakubOnderka\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://id.provider.com', 'ClientIDHere', 'ClientSecretHere');
$data = $oidc->introspectToken('an.access-token.as.given');
if (!$data->active) {
    // the token is no longer usable
}
```

## Example 8: PKCE Client

```php
use JakubOnderka\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://id.provider.com', 'ClientIDHere');
$oidc->setCodeChallengeMethod('S256');
$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
```

## Development Environments
In some cases you may need to disable SSL security on your development systems.
Note: This is not recommended on production systems.

```php
$oidc->setVerifyHost(false);
$oidc->setVerifyPeer(false);
```

Also, your local system might not support HTTPS, so you might disable upgrading to it:

```php
$oidc->httpUpgradeInsecureRequests(false);
```

### Todo
- Dynamic registration does not support registration auth tokens and endpoints

  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
  
## Contributing
 - All pull requests, once merged, should be added to the CHANGELOG.md file.
