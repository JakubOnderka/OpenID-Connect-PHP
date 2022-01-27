<?php
declare(strict_types=1);
/**
 *
 * Copyright MITRE 2020
 *
 * OpenIDConnectClient for PHP5
 * Author: Michael Jett <mjett@mitre.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

namespace Jumbojett;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Curves;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;

/**
 *
 * JWT signature verification support by Jonathan Reed <jdreed@mit.edu>
 * Licensed under the same license as the rest of this file.
 *
 * phpseclib is required to validate the signatures of some tokens.
 * It can be downloaded from: http://phpseclib.sourceforge.net/
 */

/**
 * A wrapper around base64_decode which decodes Base64URL-encoded data,
 * which is not the same alphabet as base64.
 * @param string $base64url
 * @return string
 * @throws \RuntimeException
 */
function base64url_decode(string $base64url): string {
    $base64 = strtr($base64url, '-_', '+/');
    $decoded = base64_decode($base64, true);
    if ($decoded === false) {
        throw new \RuntimeException("Could not decode string as base64.");
    }
    return $decoded;
}

/**
 * @param string $str
 * @return string
 */
function base64url_encode(string $str): string {
    $enc = base64_encode($str);
    $enc = rtrim($enc, '=');
    $enc = strtr($enc, '+/', '-_');
    return $enc;
}

if (!function_exists('str_ends_with')) {
    /**
     * `str_ends_with` function is available since PHP8,
     * @param string $haystack
     * @param string $needle
     * @return bool
     */
    function str_ends_with(string $haystack, string $needle): bool {
        $needleLen = strlen($needle);
        return $needleLen === 0 || substr_compare($haystack, $needle, -$needleLen) === 0;
    }
}

class JsonException extends \Exception
{

}

/**
 * OpenIDConnect Exception Class
 */
class OpenIDConnectClientException extends \Exception
{

}

abstract class JwkEcFormat
{
    /**
     * @param mixed $key
     * @param string|null $password Not used, only public key supported
     * @return array|false
     * @throws \RuntimeException
     */
    public static function load($key, $password)
    {
        if (!is_object($key)) {
            return false;
        }

        $curve = self::getCurve($key->crv);

        $x = new BigInteger(base64url_decode($key->x), 256);
        $y = new BigInteger(base64url_decode($key->y), 256);

        $QA = [
            $curve->convertInteger($x),
            $curve->convertInteger($y),
        ];
        if (!$curve->verifyPoint($QA)) {
            throw new \RuntimeException('Unable to verify that point exists on curve');
        }
        return ['curve' => $curve, 'QA' => $QA];
    }

    /**
     * @throws \RuntimeException
     */
    private static function getCurve(string $curveName): EC\BaseCurves\Prime
    {
        switch ($curveName) {
            case 'P-256':
                return new Curves\nistp256();
            case 'P-384':
                return new Curves\nistp384();
            case 'P-521':
                return new Curves\nistp521();
        }
        throw new \RuntimeException("Unsupported curve $curveName");
    }
}

/**
 * Require the CURL and JSON PHP extensions to be installed
 */
if (!function_exists('curl_init')) {
    throw new OpenIDConnectClientException('OpenIDConnect needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
    throw new OpenIDConnectClientException('OpenIDConnect needs the JSON PHP extension.');
}

/**
 *
 * Please note this class stores nonces by default in $_SESSION['openid_connect_nonce']
 *
 */
class OpenIDConnectClient
{
    // Session keys
    const NONCE = 'openid_connect_nonce',
        STATE = 'openid_connect_state',
        CODE_VERIFIER = 'openid_connect_code_verifier';

    // APCu cache keys
    const KEYS_CACHE = 'openid_connect_key_',
        WELLKNOWN_CACHE = 'openid_connect_wellknown_';

    /**
     * @var string arbitrary id value
     */
    private $clientID;

    /**
     * @var string arbitrary name value
     */
    private $clientName;

    /**
     * @var string arbitrary secret value
     */
    private $clientSecret;

    /**
     * @var array holds the provider configuration
     */
    private $providerConfig = [];

    /**
     * @var string|null http proxy if necessary
     */
    private $httpProxy;

    /**
     * @var string|null Full system path to the SSL/TLS public certificate
     */
    private $certPath;

    /**
     * @var bool Verify SSL peer on transactions
     */
    private $verifyPeer = true;

    /**
     * @var bool Verify peer hostname on transactions
     */
    private $verifyHost = true;

    /**
     * @var string|null if we acquire an access token it will be stored here
     */
    protected $accessToken;

    /**
     * @var string if we acquire a refresh token it will be stored here
     */
    private $refreshToken;

    /**
     * @var string if we acquire an id token it will be stored here
     */
    protected $idToken;

    /**
     * @var \stdClass stores the token response
     */
    private $tokenResponse;

    /**
     * @var array holds scopes
     */
    private $scopes = [];

    /**
     * @var array holds response types
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
     */
    private $responseTypes = [];

    /**
     * @var \stdClass|null holds a cache of info returned from the user info endpoint
     */
    private $userInfo;

    /**
     * @var array holds authentication parameters
     */
    private $authParams = [];

    /**
     * @var array holds additional registration parameters for example post_logout_redirect_uris
     */
    private $registrationParams = [];

    /**
     * @var mixed holds well-known openid server properties
     */
    private $wellKnown = false;

    /**
     * @var mixed holds well-known opendid configuration parameters, like policy for MS Azure AD B2C User Flow  
     * @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/user-flow-overview 
     */
    private $wellKnownConfigParameters = [];

    /**
     * @var int timeout (seconds)
     */
    protected $timeOut = 60;

    /**
     * This can fix clock skew between systems
     * @var int leeway (seconds)
     */
    private $leeway = 300;

    /**
     * @var array holds response types
     */
    private $additionalJwks = [];

    /**
     * @var object holds verified jwt claims
     */
    protected $verifiedClaims;

    /**
     * @var \Closure validator function for issuer claim
     */
    private $issuerValidator;

    /**
     * @var bool Allow OAuth 2 implicit flow; see http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     */
    private $allowImplicitFlow = false;

    /**
     * @var string
     */
    private $redirectURL;

    /**
     * @var int
     */
    protected $enc_type = PHP_QUERY_RFC1738;

    /**
     * @var bool Enable or disable upgrading to HTTPS by paying attention to HTTP header HTTP_UPGRADE_INSECURE_REQUESTS
     */
    protected $httpUpgradeInsecureRequests = true;

    /**
     * @var string|null holds code challenge method for PKCE mode
     * @see https://tools.ietf.org/html/rfc7636
     */
    private $codeChallengeMethod;

    /**
     * @var array holds PKCE supported algorithms
     */
    const PKCE_ALGS = ['S256' => 'sha256', 'plain' => false];

    /**
     * How long should be stored wellknown JSON in apcu cache in seconds. Use zero to disable caching.
     * @var int
     */
    private $wellknownCacheExpiration = 86400; // one day

    /**
     * How long should be stored key in apcu cache in seconds, Use zero to disable caching.
     * @var int
     */
    private $keyCacheExpiration = 86400; // one day

    /**
     * @var resource CURL handle
     */
    private $ch;

    /**
     * @var string|null
     */
    private $tokenAuthenticationMethod;

    /**
     * @param string|null $providerUrl
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @param string|null $issuer If not provided, $providerUrl will be used as issuer
     */
    public function __construct(string $providerUrl = null, string $clientId = null, string $clientSecret = null, string $issuer = null)
    {
        $this->providerConfig['providerUrl'] = $providerUrl;
        $this->providerConfig['issuer'] = $issuer ?: $providerUrl;
        $this->clientID = $clientId;
        $this->clientSecret = $clientSecret;

        $this->issuerValidator = function(string $iss): bool {
	        return $iss === $this->getIssuer() || $iss === $this->getWellKnownIssuer() || $iss === $this->getWellKnownIssuer(true);
        };
    }

    public function setProviderURL(string $providerUrl)
    {
        $this->providerConfig['providerUrl'] = $providerUrl;
    }

    public function setIssuer(string $issuer)
    {
        $this->providerConfig['issuer'] = $issuer;
    }

    /**
     * @param string|array $responseTypes
     * @return void
     */
    public function setResponseTypes($responseTypes)
    {
        $this->responseTypes = array_merge($this->responseTypes, (array)$responseTypes);
    }

    /**
     * @return bool
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function authenticate(): bool
    {
        // Do a preemptive check to see if the provider has thrown an error from a previous redirect
        if (isset($_REQUEST['error'])) {
            $desc = isset($_REQUEST['error_description']) ? ' Description: ' . $_REQUEST['error_description'] : '';
            throw new OpenIDConnectClientException('Error: ' . $_REQUEST['error'] . $desc);
        }

        // If we have an authorization code then proceed to request a token
        if (isset($_REQUEST['code'])) {
            $code = $_REQUEST['code'];
            $tokenJson = $this->requestTokens($code);

            // Throw an error if the server returns one
            if (isset($tokenJson->error)) {
                if (isset($tokenJson->error_description)) {
                    throw new OpenIDConnectClientException('Error received from IdP: ' . $tokenJson->error_description);
                }
                throw new OpenIDConnectClientException('Got response: ' . $tokenJson->error);
            }

            // Do an OpenID Connect session check
            if ($_REQUEST['state'] !== $this->getSessionKey(self::STATE)) {
                throw new OpenIDConnectClientException('Unable to determine state');
            }

            // Cleanup state
            $this->unsetSessionKey(self::STATE);

            if (!isset($tokenJson->id_token)) {
                throw new OpenIDConnectClientException('User did not authorize openid scope.');
            }

            $claims = $this->decodeJWT($tokenJson->id_token, 1);

            // Verify the signature
            if (!$this->verifyJwtSignature($tokenJson->id_token)) {
                throw new OpenIDConnectClientException ('Unable to verify signature of ID token');
            }

            // Save the id token
            $this->idToken = $tokenJson->id_token;

            // Save the access token
            $this->accessToken = $tokenJson->access_token;

            // If this is a valid claim
            if ($this->verifyJwtClaims($claims, $tokenJson->access_token)) {
                // Clean up the session a little
                $this->unsetSessionKey(self::NONCE);

                // Save the full response
                $this->tokenResponse = $tokenJson;

                // Save the verified claims
                $this->verifiedClaims = $claims;

                // Save the refresh token, if we got one
                if (isset($tokenJson->refresh_token)) {
                    $this->refreshToken = $tokenJson->refresh_token;
                }

                // Success!
                return true;
            }

            throw new OpenIDConnectClientException ('Unable to verify JWT claims');
        }

        if ($this->allowImplicitFlow && isset($_REQUEST['id_token'])) {
            // if we have no code but an id_token use that
            $id_token = $_REQUEST['id_token'];

            $accessToken = null;
            if (isset($_REQUEST['access_token'])) {
                $accessToken = $_REQUEST['access_token'];
            }

            // Do an OpenID Connect session check
            if ($_REQUEST['state'] !== $this->getSessionKey(self::STATE)) {
                throw new OpenIDConnectClientException('Unable to determine state');
            }

            // Cleanup state
            $this->unsetSessionKey(self::STATE);

            $claims = $this->decodeJWT($id_token, 1);

            // Verify the signature
            if (!$this->verifyJwtSignature($id_token)) {
                throw new OpenIDConnectClientException ('Unable to verify signature');
            }

            // Save the id token
            $this->idToken = $id_token;

            // If this is a valid claim
            if ($this->verifyJwtClaims($claims, $accessToken)) {

                // Clean up the session a little
                $this->unsetSessionKey(self::NONCE);

                // Save the verified claims
                $this->verifiedClaims = $claims;

                // Save the access token
                if ($accessToken) {
                    $this->accessToken = $accessToken;
                }

                // Success!
                return true;
            }

            throw new OpenIDConnectClientException ('Unable to verify JWT claims');
        }

        $this->requestAuthorization();
        return false;
    }

    /**
     * It calls the end-session endpoint of the OpenID Connect provider to notify the OpenID
     * Connect provider that the end-user has logged out of the relying party site
     * (the client application).
     *
     * @param string $idToken ID token (obtained at login)
     * @param string|null $redirect URL to which the RP is requesting that the End-User's User Agent
     * be redirected after a logout has been performed. The value MUST have been previously
     * registered with the OP. Value can be null.
     *
     * @throws OpenIDConnectClientException
     */
    public function signOut($idToken, $redirect = null) {
        $signout_endpoint = $this->getProviderConfigValue('end_session_endpoint');

        $signout_params = null;
        if($redirect === null){
            $signout_params = array('id_token_hint' => $idToken);
        }
        else {
            $signout_params = array(
                'id_token_hint' => $idToken,
                'post_logout_redirect_uri' => $redirect);
        }

        $signout_endpoint  .= (strpos($signout_endpoint, '?') === false ? '?' : '&') . http_build_query( $signout_params, '', '&', $this->enc_type);
        $this->redirect($signout_endpoint);
    }

    /**
     * @param array|string $scope - example: openid, given_name, etc...
     */
    public function addScope($scope)
    {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    /**
     * @param array|string $param - example: prompt=login
     */
    public function addAuthParam($param)
    {
        $this->authParams = array_merge($this->authParams, (array)$param);
    }

    /**
     * @param array|string $param - example: post_logout_redirect_uris=[http://example.com/successful-logout]
     */
    public function addRegistrationParam($param)
    {
        $this->registrationParams = array_merge($this->registrationParams, (array)$param);
    }

    /**
     * Add additional JSON Web Key, that will append to keys fetched from remote server
     * @param \stdClass $jwk - example: (object) array('kid' => ..., 'nbf' => ..., 'use' => 'sig', 'kty' => "RSA", 'e' => "", 'n' => "")
     */
    protected function addAdditionalJwk(\stdClass $jwk)
    {
        $this->additionalJwks[] = $jwk;
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param string $param
     * @param mixed|null $default
     * @throws OpenIDConnectClientException
     * @throws JsonException
     * @return mixed
     */
    protected function getProviderConfigValue(string $param, $default = null)
    {
        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if (!isset($this->providerConfig[$param])) {
            $this->providerConfig[$param] = $this->getWellKnownConfigValue($param, $default);
        }

        return $this->providerConfig[$param];
    }

    /**
     * @return \stdClass
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    private function fetchWellKnown(): \stdClass
    {
        if (str_ends_with($this->getProviderURL(), '/.well-known/openid-configuration')) {
            $wellKnownConfigUrl = $this->getProviderURL();
        } else {
            $wellKnownConfigUrl = rtrim($this->getProviderURL(), '/') . '/.well-known/openid-configuration';
        }

        if (!empty($this->wellKnownConfigParameters)) {
            $wellKnownConfigUrl .= '?' .  http_build_query($this->wellKnownConfigParameters);
        }

        if ($this->wellknownCacheExpiration && function_exists('apcu_fetch')) {
            $wellKnown = apcu_fetch(self::WELLKNOWN_CACHE . md5($wellKnownConfigUrl));
            if ($wellKnown) {
                return $wellKnown;
            }
        }

        $wellKnown = $this->jsonDecode($this->fetchURL($wellKnownConfigUrl));

        if ($this->wellknownCacheExpiration && function_exists('apcu_store')) {
            apcu_store(self::WELLKNOWN_CACHE . md5($wellKnownConfigUrl), $wellKnown, $this->wellknownCacheExpiration);
        }

        return $wellKnown;
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param string $param
     * @param mixed|null $default optional
     * @return mixed
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    private function getWellKnownConfigValue(string $param, $default = null)
    {
        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if (!$this->wellKnown) {
            $this->wellKnown = $this->fetchWellKnown();
        }

        $value = false;
        if (isset($this->wellKnown->{$param})){
            $value = $this->wellKnown->{$param};
        }

        if ($value) {
            return $value;
        }

        if (isset($default)) {
            // Uses default value if provided
            return $default;
        }

        throw new OpenIDConnectClientException("The provider {$param} could not be fetched. Make sure your provider has a well known configuration available.");
    }

    /**
     * Set optional parameters for .well-known/openid-configuration
     *
     * @param array $params
     */
    public function setWellKnownConfigParameters(array $params = [])
    {
        $this->wellKnownConfigParameters = $params;
    }

    /**
     * @param string $url Sets redirect URL for auth flow
     */
    public function setRedirectURL(string $url)
    {
        if (parse_url($url,PHP_URL_HOST) !== false) {
            $this->redirectURL = $url;
        }
        throw new \InvalidArgumentException("Invalid redirect URL provided");
    }

    /**
     * Gets the URL of the current page we are on, encodes, and returns it
     *
     * @return string
     */
    public function getRedirectURL(): string
    {
        // If the redirect URL has been set then return it.
        if ($this->redirectURL) {
            return $this->redirectURL;
        }

        // Other-wise return the URL of the current page

        /**
         * Thank you
         * http://stackoverflow.com/questions/189113/how-do-i-get-current-page-full-url-in-php-on-a-windows-iis-server
         */

        /*
         * Compatibility with multiple host headers.
         * The problem with SSL over port 80 is resolved and non-SSL over port 443.
         * Support of 'ProxyReverse' configurations.
         */
        if ($this->httpUpgradeInsecureRequests && isset($_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS']) && $_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'] === '1') {
            $protocol = 'https';
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            $protocol = $_SERVER['HTTP_X_FORWARDED_PROTO'];
        } elseif (isset($_SERVER['REQUEST_SCHEME'])) {
            $protocol = $_SERVER['REQUEST_SCHEME'];
        } elseif (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            $protocol = 'https';
        } else {
            $protocol = 'http';
        }
	    
        if (isset($_SERVER['HTTP_X_FORWARDED_PORT'])) {
            $port = (int)$_SERVER['HTTP_X_FORWARDED_PORT'];
        } elseif (isset($_SERVER['SERVER_PORT'])) {
            $port = (int)$_SERVER['SERVER_PORT'];
        } elseif ($protocol === 'https') {
            $port = 443;
        } else {
            $port = 80;
        }

        if (isset($_SERVER['HTTP_HOST'])) {
            $host = explode(':', $_SERVER['HTTP_HOST'])[0];
        } elseif (isset($_SERVER['SERVER_NAME'])) {
            $host = $_SERVER['SERVER_NAME'];
        } elseif (isset($_SERVER['SERVER_ADDR'])) {
            $host = $_SERVER['SERVER_ADDR'];
        } else {
            return 'http:///';
        }

        $port = (443 === $port || 80 === $port) ? '' : ':' . $port;
	    
        $explodedRequestUri = isset($_SERVER['REQUEST_URI']) ? trim(explode('?', $_SERVER['REQUEST_URI'])[0], '/') : '';
        return "$protocol://$host$port/$explodedRequestUri";
    }

    /**
     * Used for arbitrary value generation for nonces and state
     *
     * @return string
     * @throws \Exception
     */
    protected function generateRandString(): string
    {
        return base64url_encode(\random_bytes(16));
    }

    /**
     * Start Here
     * @return void
     * @throws OpenIDConnectClientException
     * @throws JsonException
     * @throws \Exception
     */
    private function requestAuthorization()
    {
        $authEndpoint = $this->getProviderConfigValue('authorization_endpoint');

        // Generate and store a nonce in the session
        // The nonce is an arbitrary value
        $nonce = $this->generateRandString();
        $this->setSessionKey(self::NONCE, $nonce);

        // State essentially acts as a session key for OIDC
        $state = $this->generateRandString();
        $this->setSessionKey(self::STATE, $state);

        $authParams = array_merge($this->authParams, [
            'response_type' => 'code',
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'nonce' => $nonce,
            'state' => $state,
            'scope' => 'openid'
        ]);

        // If the client has been registered with additional scopes
        if (!empty($this->scopes)) {
            $authParams['scope'] = implode(' ', array_merge($this->scopes, ['openid']));
        }

        // If the client has been registered with additional response types
        if (!empty($this->responseTypes)) {
            $authParams['response_type'] = implode(' ', $this->responseTypes);
        }

        // If the client supports Proof Key for Code Exchange (PKCE)
        $ccm = $this->getCodeChallengeMethod();
        if (!empty($ccm) && in_array($ccm, $this->getProviderConfigValue('code_challenge_methods_supported'), true)) {
            $codeVerifier = base64url_encode(random_bytes(32));
            $this->setSessionKey(self::CODE_VERIFIER, $codeVerifier);

            if (!empty(self::PKCE_ALGS[$ccm])) {
                $codeChallenge = base64url_encode(hash(self::PKCE_ALGS[$ccm], $codeVerifier, true));
            } else {
                $codeChallenge = $codeVerifier;
            }
            $authParams = array_merge($authParams, [
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => $ccm,
            ]);
        }

        // If auth endpoint already contains params, just append &
        $authEndpoint .= strpos($authEndpoint, '?') === false ? '?' : '&';
        $authEndpoint .= http_build_query($authParams, '', '&', $this->enc_type);

        $this->commitSession();
        $this->redirect($authEndpoint);
    }

    /**
     * Requests a client credentials token
     *
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function requestClientCredentialsToken()
    {
        $token_endpoint = $this->getProviderConfigValue('token_endpoint');

        $headers = [];

        $grant_type = 'client_credentials';

        $post_data = array(
            'grant_type'    => $grant_type,
            'client_id'     => $this->clientID,
            'client_secret' => $this->clientSecret,
            'scope'         => implode(' ', $this->scopes)
        );

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&', $this->enc_type);

        return json_decode($this->fetchURL($token_endpoint, $post_params, $headers));
    }


    /**
     * Requests a resource owner token
     * (Defined in https://tools.ietf.org/html/rfc6749#section-4.3)
     *
     * @param boolean $bClientAuth Indicates that the Client ID and Secret be used for client authentication
     * @return mixed
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function requestResourceOwnerToken($bClientAuth = false)
    {
        $token_endpoint = $this->getProviderConfigValue('token_endpoint');

        $headers = [];

        $grant_type = 'password';

        $post_data = array(
            'grant_type'    => $grant_type,
            'username'      => $this->authParams['username'],
            'password'      => $this->authParams['password'],
            'scope'         => implode(' ', $this->scopes)
        );

        //For client authentication include the client values
        if($bClientAuth) {
            $token_endpoint_auth_methods_supported = $this->getProviderConfigValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);
            if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported, true)) {
                $headers = ['Authorization: Basic ' . base64_encode(urlencode($this->clientID) . ':' . urlencode($this->clientSecret))];
            } else {
                $post_data['client_id']     = $this->clientID;
                $post_data['client_secret'] = $this->clientSecret;
            }
        }

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&', $this->enc_type);

        return json_decode($this->fetchURL($token_endpoint, $post_params, $headers));
    }

    /**
     * Requests ID and Access tokens
     *
     * @param string $code
     * @return \stdClass
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    protected function requestTokens(string $code): \stdClass
    {
        $tokenEndpointAuthMethodsSupported = $this->getProviderConfigValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);
        if ($this->tokenAuthenticationMethod && !in_array($this->tokenAuthenticationMethod, $tokenEndpointAuthMethodsSupported)) {
            $supportedMethods = implode(", ", $tokenEndpointAuthMethodsSupported);
            throw new OpenIDConnectClientException("Token authentication method {$this->tokenAuthenticationMethod} is not supported by IdP. Supported methods are: $supportedMethods");
        }

        if ($this->tokenAuthenticationMethod === 'client_secret_jwt') {
            return $this->requestTokensClientSecretJwt($code);
        }

        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');

        $headers = [];
        $tokenParams = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret,
        ];

        // Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $tokenEndpointAuthMethodsSupported, true) && $this->tokenAuthenticationMethod !== 'client_secret_post') {
            $headers = [$this->basicAuthorizationHeader($this->clientID, $this->clientSecret)];
            unset($tokenParams['client_secret']);
	        unset($tokenParams['client_id']);
        }

        $ccm = $this->getCodeChallengeMethod();
        $cv = $this->getSessionKey(self::CODE_VERIFIER);
        if (!empty($ccm) && !empty($cv)) {
            $headers = [];
            unset($tokenParams['client_secret']);
            $tokenParams = array_merge($tokenParams, [
                'client_id' => $this->clientID,
                'code_verifier' => $cv,
            ]);
        }

        $this->tokenResponse = $this->jsonDecode($this->fetchURL($tokenEndpoint, $tokenParams, $headers));
        return $this->tokenResponse;
    }

    /**
     * @throws OpenIDConnectClientException
     * @throws JsonException
     * @throws \Exception
     * @see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
     */
    protected function requestTokensClientSecretJwt(string $code): \stdClass
    {
        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');

        $time = time();
        $jwt = $this->createHmacSignedJwt([
            'iss' => $this->clientID,
            'sub' => $this->clientID,
            'aud' => $tokenEndpoint,
            'jti' => $this->generateRandString(),
            'exp' => $time + $this->timeOut,
            'iat' => $time,
        ], 'HS256', $this->clientSecret);

        $tokenParams = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $jwt,
        ];

        $this->tokenResponse = $this->jsonDecode($this->fetchURL($tokenEndpoint, $tokenParams));
        return $this->tokenResponse;
    }

    /**
     * Requests Access token with refresh token
     *
     * @param string $refreshToken
     * @return \stdClass
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function refreshToken(string $refreshToken): \stdClass
    {
        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');
        $tokenEndpointAuthMethodsSupported = $this->getProviderConfigValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);

        $headers = [];

        $tokenParams = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret,
            'scope' => implode(' ', $this->scopes),
        ];

        // Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $tokenEndpointAuthMethodsSupported, true)) {
            $headers = [$this->basicAuthorizationHeader($this->clientID, $this->clientSecret)];
            unset($tokenParams['client_secret']);
            unset($tokenParams['client_id']);
        }

        $json = $this->jsonDecode($this->fetchURL($tokenEndpoint, $tokenParams, $headers));

        if (isset($json->access_token)) {
            $this->accessToken = $json->access_token;
        }

        if (isset($json->refresh_token)) {
            $this->refreshToken = $json->refresh_token;
        }

        return $json;
    }

    /**
     * @param \stdClass $key
     * @return AsymmetricKey
     * @throws OpenIDConnectClientException
     */
    private function convertJwtToAsymmetricKey(\stdClass $key): AsymmetricKey
    {
        if (!isset($key->kty)) {
            throw new OpenIDConnectClientException("Malformed key object, `kty` field is missing");
        }

        if ($key->kty === 'EC') {
            if (!isset($key->x) || !isset($key->y) || !isset($key->crv)) {
                throw new OpenIDConnectClientException('Malformed EC key object');
            }

            EC::addFileFormat(JwkEcFormat::class);
            return EC::load($key);

        } else if ($key->kty === 'RSA') {
            if (!isset($key->n) || !isset($key->e)) {
                throw new OpenIDConnectClientException('Malformed RSA key object');
            }

            // Decode public key from base64url to binary, we don't need to use constant time impl for public key
            $modulus = new BigInteger(base64url_decode($key->n), 256);
            $exponent = new BigInteger(base64url_decode($key->e), 256);
            $publicKeyRaw = [
                'modulus' => $modulus,
                'exponent' => $exponent,
            ];
            return RSA::load($publicKeyRaw);
        }
        throw new OpenIDConnectClientException("Not supported key type $key->kty");
    }

    /**
     * @param object $header
     * @param string $type
     * @return AsymmetricKey
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    private function fetchKeyForHeader($header, string $type): AsymmetricKey
    {
        $jwksUri = $this->getProviderConfigValue('jwks_uri');
        if (!$jwksUri) {
            throw new OpenIDConnectClientException ('Unable to verify signature due to no jwks_uri being defined');
        }

        if (function_exists('apcu_fetch') && $this->keyCacheExpiration > 0) {
            $cacheKey = self::KEYS_CACHE . md5($jwksUri);
            $jwks = apcu_fetch($cacheKey);
            if ($jwks) {
                try {
                    return $this->convertJwtToAsymmetricKey($this->getKeyForHeader($jwks->keys, $header, $type));
                } catch (\Exception $e) {
                    // ignore if key not found and fetch key from server again
                }
            }
        }

        try {
            $jwks = $this->jsonDecode($this->fetchURL($jwksUri));
        } catch (\Exception $e) {
            throw new OpenIDConnectClientException('Error fetching JSON from jwks_uri', 0, $e);
        }

        if (isset($cacheKey)) {
            apcu_store($cacheKey, $jwks, $this->keyCacheExpiration);
        }

        $key = $this->getKeyForHeader($jwks->keys, $header, $type);
        return $this->convertJwtToAsymmetricKey($key);
    }

    /**
     * @param array $keys
     * @param object $header
     * @param string $type 'RSA' or 'EC'
     * @throws OpenIDConnectClientException
     * @return object
     */
    private function getKeyForHeader(array $keys, $header, string $type)
    {
        foreach (array_merge($keys, $this->additionalJwks) as $key) {
            if ($key->kty === $type) {
                if (!isset($header->kid) || $key->kid === $header->kid) {
                    return $key;
                }
            } else {
                if (isset($key->alg) && $key->alg === $header->alg && $key->kid === $header->kid) {
                    return $key;
                }
            }
        }
        if (isset($header->kid)) {
            throw new OpenIDConnectClientException("Unable to find a key for {$header->alg} with kid `{$header->kid}`");
        }
        throw new OpenIDConnectClientException("Unable to find a key for $type");
    }

    /**
     * @param string $hashType
     * @param RSA $key
     * @param string $payload
     * @param string $signature
     * @param bool $isPss
     * @return bool
     * @throws OpenIDConnectClientException
     */
    private function verifyRsaJwtSignature(string $hashType, RSA $key, string $payload, string $signature, bool $isPss): bool
    {
        $rsa = $key->withHash($hashType);
        if ($isPss) {
            $rsa = $rsa->withMGFHash($hashType)
                ->withPadding(RSA::SIGNATURE_PSS);
        } else {
            $rsa = $rsa->withPadding(RSA::SIGNATURE_PKCS1);
        }
        return $rsa->verify($payload, $signature);
    }

    /**
     * @param string $hashType
     * @param string $key
     * @param string $payload
     * @param string $signature
     * @return bool
     * @throws OpenIDConnectClientException
     */
    private function verifyHmacJwtSignature(string $hashType, string $key, string $payload, string $signature): bool
    {
        if (!function_exists('hash_hmac')) {
            throw new OpenIDConnectClientException('hash_hmac support unavailable.');
        }

        $expected = hash_hmac($hashType, $payload, $key, true);
        return hash_equals($signature, $expected);
    }

    /**
     * @param string $hashType
     * @param EC $ec
     * @param string $payload
     * @param string $signature
     * @return bool
     * @throws OpenIDConnectClientException
     */
    private function verifyEcJwtSignature(string $hashType, EC $ec, string $payload, string $signature): bool
    {
        $half = strlen($signature) / 2;
        if (!is_int($half)) {
            throw new OpenIDConnectClientException("Signature has invalid length");
        }
        $rawSignature = [
            'r' => new BigInteger(substr($signature, 0, $half), 256),
            's' => new BigInteger(substr($signature, $half), 256),
        ];
        return $ec->withSignatureFormat('raw')->withHash($hashType)->verify($payload, $rawSignature);
    }

    /**
     * @param string $jwt encoded JWT
     * @return bool
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function verifyJwtSignature(string $jwt): bool
    {
        $parts = explode('.', $jwt);
        if (!isset($parts[0])) {
            throw new OpenIDConnectClientException('Error missing part 0 in token');
        }

        try {
            $signature = base64url_decode(array_pop($parts));
            if ('' === $signature) {
                throw new \Exception('Decoded signature is empty string');
            }
        } catch (\Exception $e) {
            throw new OpenIDConnectClientException('Error decoding signature from token', 0, $e);
        }

        try {
            $header = $this->jsonDecode(base64url_decode($parts[0]));
        } catch (\Exception $e) {
            throw new OpenIDConnectClientException('Error decoding token header', 0, $e);
        }

        if (!isset($header->alg)) {
            throw new OpenIDConnectClientException('Error missing signature type in token header');
        }

        $payload = implode('.', $parts);
        switch ($header->alg) {
            case 'RS256':
            case 'PS256':
            case 'RS384':
            case 'PS384':
            case 'RS512':
            case 'PS512':
                $hashType = 'sha' . substr($header->alg, 2);
                $isPss = $header->alg[0] === 'P';
                $key = $this->fetchKeyForHeader($header, 'RSA');
                return $this->verifyRsaJwtSignature($hashType, $key, $payload, $signature, $isPss);
            case 'HS256':
            case 'HS512':
            case 'HS384':
                $hashType = 'SHA' . substr($header->alg, 2);
                return $this->verifyHmacJwtSignature($hashType, $this->getClientSecret(), $payload, $signature);
            case 'ES256':
            case 'ES384':
            case 'ES512':
                $hashType = 'SHA' . substr($header->alg, 2);
                $key = $this->fetchKeyForHeader($header, 'EC');
                return $this->verifyEcJwtSignature($hashType, $key, $payload, $signature);
        }
        throw new OpenIDConnectClientException('No support for signature type: ' . $header->alg);
    }

    /**
     * Validate ID token and access token if provided. See https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     * @param object $claims
     * @param string|null $accessToken
     * @return true
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    protected function verifyJwtClaims($claims, string $accessToken = null): bool
    {
        if (isset($claims->at_hash) && isset($accessToken)) {
            $idTokenHeader = $this->getIdTokenHeader();
            if (isset($idTokenHeader->alg) && $idTokenHeader->alg !== 'none') {
                $bit = substr($idTokenHeader->alg, 2, 3);
            } else {
                // This should never happened, because alg is already checked in verifyJWTsignature method
                throw new OpenIDConnectClientException("Invalid ID token alg");
            }
            $len = ((int) $bit) / 16;
            $expectedAtHash = base64url_encode(substr(hash('sha' . $bit, $accessToken, true), 0, $len));
        }

        if (!($this->issuerValidator)($claims->iss)) {
            throw new OpenIDConnectClientException("Could not validate claims, it didn't pass issuer validator");
        }

        // Audience
        if ($claims->aud !== $this->clientID && !in_array($this->clientID, (array)$claims->aud, true)) {
            throw new OpenIDConnectClientException("Could not validate claims, client ID do not match");
        }

        if (isset($claims->nonce) && $claims->nonce !== $this->getSessionKey(self::NONCE)) {
            throw new OpenIDConnectClientException("Could not validate claims, nonce do not match");
        }

        // Expiration Time
        if (isset($claims->exp) && is_int($claims->exp) && ($claims->exp < time() - $this->leeway)) {
            throw new OpenIDConnectClientException("Could not validate claims, token is already expired");
        }

        // Not Before
        if (isset($claims->nbf) && is_int($claims->nbf) && ($claims->nbf > time() + $this->leeway)) {
            throw new OpenIDConnectClientException("Could not validate claims, token is not valid yet");
        }

        if (isset($claims->at_hash) && isset($expectedAtHash) && !hash_equals($expectedAtHash, $claims->at_hash)) {
            throw new OpenIDConnectClientException("Could not validate claims, at_hash do not match");
        }

        return true;
    }

    /**
     * @param string $jwt encoded JWT
     * @param int $section the section we would like to decode
     * @return \stdClass
     * @throws \RuntimeException
     * @throws JsonException
     */
    protected function decodeJWT(string $jwt, int $section = 0): \stdClass
    {
        $parts = explode('.', $jwt);
        if (!isset($parts[$section])) {
            throw new \RuntimeException("Section $section is not included in JWT token");
        }
        return $this->jsonDecode(base64url_decode($parts[$section]));
    }

    /**
     * @param string|null $attribute Name of the attribute to get. If null, all attributes will be returned
     *
     * Attribute        Type        Description
     * user_id          string      REQUIRED Identifier for the End-User at the Issuer.
     * name             string      End-User's full name in displayable form including all name parts, ordered according to End-User's locale and preferences.
     * given_name       string      Given name or first name of the End-User.
     * family_name      string      Surname or last name of the End-User.
     * middle_name      string      Middle name of the End-User.
     * nickname         string      Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
     * profile          string      URL of End-User's profile page.
     * picture          string      URL of the End-User's profile picture.
     * website          string      URL of End-User's web page or blog.
     * email            string      The End-User's preferred e-mail address.
     * verified         boolean     True if the End-User's e-mail address has been verified; otherwise false.
     * gender           string      The End-User's gender: Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
     * birthday         string      The End-User's birthday, represented as a date string in MM/DD/YYYY format. The year MAY be 0000, indicating that it is omitted.
     * zoneinfo         string      String from zoneinfo [zoneinfo] time zone database. For example, Europe/Paris or America/Los_Angeles.
     * locale           string      The End-User's locale, represented as a BCP47 [RFC5646] language tag.
     *                              This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash.
     *                              For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Implementations MAY choose to accept this locale syntax as well.
     * phone_number     string      The End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim. For example, +1 (425) 555-1212 or +56 (2) 687 2400.
     * address          JSON object The End-User's preferred address. The value of the address member is a JSON [RFC4627] structure containing some or all of the members defined in Section 2.4.2.1.
     * updated_time     string      Time the End-User's information was last updated, represented as a RFC 3339 [RFC3339] datetime. For example, 2011-01-03T23:58:42+0000.
     *
     * @return mixed
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function requestUserInfo(string $attribute = null)
    {
        if (!isset($this->accessToken)) {
            throw new OpenIDConnectClientException("Access token doesn't exists");
        }

        if (!$this->userInfo) {
            $userInfoEndpoint = $this->getProviderConfigValue('userinfo_endpoint');
            $userInfoEndpoint .= '?schema=openid';

            // The accessToken has to be sent in the Authorization header.
            // Accept json to indicate response type
            $headers = [
                "Authorization: Bearer {$this->accessToken}",
                'Accept: application/json',
            ];

            $userInfo = $this->jsonDecode($this->fetchURL($userInfoEndpoint, null, $headers));
            if ($this->getResponseCode() <> 200) {
                throw new OpenIDConnectClientException('The communication to retrieve user data has failed with status code ' . $this->getResponseCode());
            }
            $this->userInfo = $userInfo;
        }

        if ($attribute === null) {
            return $this->userInfo;
        }

        if (property_exists($this->userInfo, $attribute)) {
            return $this->userInfo->$attribute;
        }

        return null;
    }

    /**
     * @param string|null $attribute
     *
     * Attribute        Type    Description
     * exp              int     Expires at
     * nbf              int     Not before
     * ver              string  Version
     * iss              string  Issuer
     * sub              string  Subject
     * aud              string  Audience
     * nonce            string  nonce
     * iat              int     Issued At
     * auth_time        int     Authentication time
     * oid              string  Object id
     *
     * @return mixed
     */
    public function getVerifiedClaims(string $attribute = null)
    {
        if ($attribute === null) {
            return $this->verifiedClaims;
        }

        if (property_exists($this->verifiedClaims, $attribute)) {
            return $this->verifiedClaims->$attribute;
        }

        return null;
    }

    /**
     * @param string $url
     * @param string|array|null $postBody string If this is set the post type will be POST
     * @param array $headers Extra headers to be send with the request. Format as 'NameHeader: ValueHeader'
     * @return string
     * @throws OpenIDConnectClientException
     */
    protected function fetchURL(string $url, $postBody = null, array $headers = []): string
    {
        if (!$this->ch) {
            $this->ch = curl_init();
        }

        curl_reset($this->ch);

        // Determine whether this is a GET or POST
        if ($postBody !== null) {
            // Default content type is form encoded
            $contentType = 'application/x-www-form-urlencoded';

            // Determine if this is a JSON payload and add the appropriate content type
            if (is_array($postBody)) {
                $postBody = http_build_query($postBody, '', '&', $this->enc_type);
            } else if (is_string($postBody) && is_object(json_decode($postBody))) {
                $contentType = 'application/json';
            } else {
                throw new \InvalidArgumentException("Invalid type for postBody, expected array, string or null value");
            }

            // curl_setopt($this->ch, CURLOPT_POST, 1);
            // Allows to keep the POST method even after redirect
            curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($this->ch, CURLOPT_POSTFIELDS, $postBody);

            // Add POST-specific headers
            $headers[] = "Content-Type: {$contentType}";
        }

        // If we set some headers include them
        if (!empty($headers)) {
            curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);
        }

        if (isset($this->httpProxy)) {
            curl_setopt($this->ch, CURLOPT_PROXY, $this->httpProxy);
        }

        /**
         * Set cert
         * Otherwise ignore SSL peer verification
         */
        if (isset($this->certPath)) {
            curl_setopt($this->ch, CURLOPT_CAINFO, $this->certPath);
        }

        curl_setopt_array($this->ch, [
            CURLOPT_URL => $url, // Set URL to download
            CURLOPT_FOLLOWLOCATION => true, // Allows to follow redirect
            CURLOPT_SSL_VERIFYPEER => $this->verifyPeer,
            CURLOPT_SSL_VERIFYHOST => $this->verifyHost ? 2 : 0,
            CURLOPT_RETURNTRANSFER => true, // Should cURL return or print out the data? (true = return, false = print)
            CURLOPT_HEADER => false, CURLOPT_HEADER, // Include header in result?
            CURLOPT_TIMEOUT => $this->timeOut, // Timeout in seconds
        ]);

        // Download the given URL, and return output
        $output = curl_exec($this->ch);

        if ($output === false) {
            throw new OpenIDConnectClientException('Curl error: (' . curl_errno($this->ch) . ') ' . curl_error($this->ch));
        }

        return $output;
    }

    /**
     * @param bool $appendSlash
     * @return string
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function getWellKnownIssuer(bool $appendSlash = false): string
    {
        return $this->getWellKnownConfigValue('issuer') . ($appendSlash ? '/' : '');
    }

    /**
     * @return string
     * @throws OpenIDConnectClientException
     */
    public function getIssuer(): string
    {
        if (!isset($this->providerConfig['issuer'])) {
            throw new OpenIDConnectClientException('The issuer has not been set');
        }
        return $this->providerConfig['issuer'];
    }

    /**
     * @return string
     * @throws OpenIDConnectClientException
     */
    public function getProviderURL(): string
    {
        if (!isset($this->providerConfig['providerUrl'])) {
            throw new OpenIDConnectClientException('The provider URL has not been set');
        }
        return $this->providerConfig['providerUrl'];
    }

    /**
     * @param string $url
     */
    public function redirect(string $url)
    {
        header('Location: ' . $url);
        exit;
    }

    /**
     * @param string|null $httpProxy
     */
    public function setHttpProxy($httpProxy)
    {
        $this->httpProxy = $httpProxy;
    }

    /**
     * @param string $certPath
     */
    public function setCertPath(string $certPath)
    {
        $this->certPath = $certPath;
    }

    /**
     * @return string|null
     */
    public function getCertPath()
    {
        return $this->certPath;
    }

    /**
     * @param bool $verifyPeer
     */
    public function setVerifyPeer(bool $verifyPeer)
    {
        $this->verifyPeer = $verifyPeer;
    }

    /**
     * @param bool $verifyHost
     */
    public function setVerifyHost(bool $verifyHost)
    {
        $this->verifyHost = $verifyHost;
    }

    /**
     * Controls whether http header HTTP_UPGRADE_INSECURE_REQUESTS should be considered
     * defaults to true
     * @param bool $httpUpgradeInsecureRequests
     */
    public function setHttpUpgradeInsecureRequests(bool $httpUpgradeInsecureRequests)
    {
        $this->httpUpgradeInsecureRequests = $httpUpgradeInsecureRequests;
    }

    /**
     * @return bool
     */
    public function getVerifyHost(): bool
    {
        return $this->verifyHost;
    }

    /**
     * @return bool
     */
    public function getVerifyPeer(): bool
    {
        return $this->verifyPeer;
    }

    /**
     * @return bool 
     */
    public function getHttpUpgradeInsecureRequests(): bool
    {
        return $this->httpUpgradeInsecureRequests;
    }

    /**
     * Use this for custom issuer validation
     * The given function should accept the issuer string from the JWT claim as the only argument
     * and return true if the issuer is valid, otherwise return false
     *
     * @param \Closure $issuerValidator
     */
    public function setIssuerValidator(\Closure $issuerValidator)
    {
        $this->issuerValidator = $issuerValidator;
    }

    /**
     * @param bool $allowImplicitFlow
     */
    public function setAllowImplicitFlow(bool $allowImplicitFlow)
    {
        $this->allowImplicitFlow = $allowImplicitFlow;
    }

    /**
     * @return bool
     */
    public function getAllowImplicitFlow(): bool
    {
        return $this->allowImplicitFlow;
    }

    /**
     * Use this to alter a provider's endpoints and other attributes
     *
     * @param array $array
     *        simple key => value
     */
    public function providerConfigParam(array $array)
    {
        $this->providerConfig = array_merge($this->providerConfig, $array);
    }

    /**
     * @param string $clientSecret
     */
    public function setClientSecret(string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @param string $clientID
     */
    public function setClientID(string $clientID)
    {
        $this->clientID = $clientID;
    }

    /**
     * Dynamic registration
     *
     * @throws OpenIDConnectClientException
     */
    public function register() {

        $registration_endpoint = $this->getProviderConfigValue('registration_endpoint');

        $send_object = (object ) array_merge($this->registrationParams, array(
            'redirect_uris' => array($this->getRedirectURL()),
            'client_name' => $this->getClientName()
        ));

        $response = $this->fetchURL($registration_endpoint, json_encode($send_object));

        $json_response = json_decode($response);

        // Throw some errors if we encounter them
        if ($json_response === false) {
            throw new OpenIDConnectClientException('Error registering: JSON response received from the server was invalid.');
        }

        if (isset($json_response->{'error_description'})) {
            throw new OpenIDConnectClientException($json_response->{'error_description'});
        }

        $this->setClientID($json_response->{'client_id'});

        // The OpenID Connect Dynamic registration protocol makes the client secret optional
        // and provides a registration access token and URI endpoint if it is not present
        if (isset($json_response->{'client_secret'})) {
            $this->setClientSecret($json_response->{'client_secret'});
        } else {
            throw new OpenIDConnectClientException('Error registering:
                                                    Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them');
        }

    }

    /**
     * Introspect a given token - either access token or refresh token.
     * @see https://tools.ietf.org/html/rfc7662
     *
     * @param string $token
     * @param string $token_type_hint
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @return mixed
     * @throws OpenIDConnectClientException
     */
    public function introspectToken($token, $token_type_hint = '', $clientId = null, $clientSecret = null) {
        $introspection_endpoint = $this->getProviderConfigValue('introspection_endpoint');

        $post_data = array(
            'token'    => $token,
        );
        if ($token_type_hint) {
            $post_data['token_type_hint'] = $token_type_hint;
        }
        $clientId = $clientId !== null ? $clientId : $this->clientID;
        $clientSecret = $clientSecret !== null ? $clientSecret : $this->clientSecret;

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&');
        $headers = ['Authorization: Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($clientSecret)),
            'Accept: application/json'];

        return json_decode($this->fetchURL($introspection_endpoint, $post_params, $headers));
    }

    /**
     * Revoke a given token - either access token or refresh token.
     * @see https://tools.ietf.org/html/rfc7009
     *
     * @param string $token
     * @param string $token_type_hint
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @return mixed
     * @throws OpenIDConnectClientException
     */
    public function revokeToken($token, $token_type_hint = '', $clientId = null, $clientSecret = null) {
        $revocation_endpoint = $this->getProviderConfigValue('revocation_endpoint');

        $post_data = array(
            'token'    => $token,
        );
        if ($token_type_hint) {
            $post_data['token_type_hint'] = $token_type_hint;
        }
        $clientId = $clientId !== null ? $clientId : $this->clientID;
        $clientSecret = $clientSecret !== null ? $clientSecret : $this->clientSecret;

        // Convert token params to string format
        $post_params = http_build_query($post_data, '', '&');
        $headers = ['Authorization: Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($clientSecret)),
            'Accept: application/json'];

        return json_decode($this->fetchURL($revocation_endpoint, $post_params, $headers));
    }

    /**
     * @return string|null
     */
    public function getClientName()
    {
        return $this->clientName;
    }

    /**
     * @param string $clientName
     */
    public function setClientName(string $clientName)
    {
        $this->clientName = $clientName;
    }

    /**
     * @return string|null
     */
    public function getClientID()
    {
        return $this->clientID;
    }

    /**
     * @return string|null
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * Set the access token.
     *
     * May be required for subclasses of this Client.
     *
     * @param string $accessToken
     * @return void
     */
    public function setAccessToken(string  $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @return string|null
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @return string|null
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return string|null
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @return \stdClass
     * @throws JsonException
     * @throws \RuntimeException
     */
    public function getAccessTokenHeader(): \stdClass
    {
        if (!isset($this->accessToken)) {
            throw new \RuntimeException("Access token not set");
        }
        return $this->decodeJWT($this->accessToken);
    }

    /**
     * @return \stdClass
     * @throws JsonException
     * @throws \RuntimeException
     */
    public function getAccessTokenPayload(): \stdClass
    {
        if (!isset($this->accessToken)) {
            throw new \RuntimeException("Access token not set");
        }
        return $this->decodeJWT($this->accessToken, 1);
    }

    /**
     * @return \stdClass
     * @throws JsonException
     * @throws \RuntimeException
     */
    public function getIdTokenHeader(): \stdClass
    {
        if (!isset($this->idToken)) {
            throw new \RuntimeException("ID token not set");
        }
        return $this->decodeJWT($this->idToken);
    }

    /**
     * @return \stdClass
     * @throws JsonException
     * @throws \RuntimeException
     */
    public function getIdTokenPayload(): \stdClass
    {
        if (!isset($this->idToken)) {
            throw new \RuntimeException("ID token not set");
        }
        return $this->decodeJWT($this->idToken, 1);
    }

    /**
     * @return \stdClass|null
     */
    public function getTokenResponse()
    {
        return $this->tokenResponse;
    }

    /**
     * Get the response code from last action/curl request.
     *
     * @return int|null
     */
    public function getResponseCode()
    {
        $info = curl_getinfo($this->ch);
        return $info['http_code'];
    }

    /**
     * Set timeout (seconds)
     *
     * @param int $timeout
     */
    public function setTimeout(int $timeout)
    {
        $this->timeOut = $timeout;
    }

    /**
     * @return int
     */
    public function getTimeout(): int
    {
        return $this->timeOut;
    }

    /**
     * Use session to manage a nonce
     */
    protected function startSession()
    {
        if (!isset($_SESSION)) {
            if (!session_start()) {
                throw new \RuntimeException("Could not start session");
            }
        }
    }

    /**
     * @return void
     */
    protected function commitSession()
    {
        if (session_write_close() === false) {
            throw new \RuntimeException("Could not write session");
        }
    }

    /**
     * Fetch given key from sessions. If session key doesn't exists, returns `null`
     * @param string $key
     * @return string|null
     */
    protected function getSessionKey(string $key)
    {
        $this->startSession();

        if (array_key_exists($key, $_SESSION)) {
            return $_SESSION[$key];
        }
        return null;
    }

    /**
     * @param string $key
     * @param string $value
     * @return void
     */
    protected function setSessionKey(string $key, string $value)
    {
        $this->startSession();

        $_SESSION[$key] = $value;
    }

    /**
     * @param string $key
     * @return void
     */
    protected function unsetSessionKey(string $key)
    {
        $this->startSession();

        unset($_SESSION[$key]);
    }

    /**
     * @param int $urlEncoding
     */
    public function setUrlEncoding(int $urlEncoding)
    {
        if (in_array($urlEncoding, [PHP_QUERY_RFC1738, PHP_QUERY_RFC3986], true)) {
            $this->enc_type = $urlEncoding;
        } else {
            throw new \InvalidArgumentException("Unsupported encoding provided");
        }
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return array
     */
    public function getResponseTypes(): array
    {
        return $this->responseTypes;
    }

    /**
     * @return array
     */
    public function getAuthParams(): array
    {
        return $this->authParams;
    }

    /**
     * @return \Closure
     */
    public function getIssuerValidator(): \Closure
    {
        return $this->issuerValidator;
    }

    /**
     * @param int $leeway In seconds
     * @return void
     */
    public function setLeeway(int $leeway)
    {
        $this->leeway = $leeway;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }

    /**
     * @return string|null
     */
    public function getCodeChallengeMethod()
    {
        return $this->codeChallengeMethod;
    }

    /**
     * @param string|null $codeChallengeMethod
     */
    public function setCodeChallengeMethod($codeChallengeMethod)
    {
        if ($codeChallengeMethod !== null && !isset(self::PKCE_ALGS[$codeChallengeMethod])) {
            throw new \InvalidArgumentException("Invalid code challenge method $codeChallengeMethod");
        }
        $this->codeChallengeMethod = $codeChallengeMethod;
    }

    /**
     *
     * @param string|null $tokenAuthenticationMethod
     * @return void
     */
    public function setTokenAuthenticationMethod($tokenAuthenticationMethod)
    {
        $this->tokenAuthenticationMethod = $tokenAuthenticationMethod;
    }

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @return string
     */
    private function basicAuthorizationHeader(string $clientId, string $clientSecret): string
    {
        return 'Authorization: Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($clientSecret));
    }

    /**
     * @param string $json
     * @return \stdClass
     * @throws JsonException
     */
    private function jsonDecode(string $json): \stdClass
    {
        if (defined('JSON_THROW_ON_ERROR')) {
            try {
                $decoded = json_decode($json, false, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new JsonException("Could not decode provided JSON", 0, $e);
            }
        } else {
            $decoded = json_decode($json);
            if ($decoded === null) {
                throw new JsonException("Could not decode provided JSON: " . json_last_error_msg());
            }
        }
        if (!is_object($decoded)) {
            throw new JsonException("Decoded JSON must be object, " . gettype($decoded) . " type received.");
        }
        return $decoded;
    }

    /**
     * @param array $payload
     * @param string $hashAlg
     * @param string $secret
     * @return string
     */
    private function createHmacSignedJwt(array $payload, string $hashAlg, string $secret): string
    {
        if (!in_array($hashAlg, ['HS256', 'HS384', 'HS512'])) {
            throw new \InvalidArgumentException("Invalid hash algorithm $hashAlg");
        }

        $header = [
            'alg' => $hashAlg,
            'typ' => 'JWT',
        ];
        $header = base64url_encode(json_encode($header));
        $payload = base64url_encode(json_encode($payload));
        $hmac = hash_hmac('sha' . substr($hashAlg, 2), "$header.$payload", $secret, true);
        $signature = base64url_encode($hmac);
        return "$header.$payload.$signature";
    }
}
