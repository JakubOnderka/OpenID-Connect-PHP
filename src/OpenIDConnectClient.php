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

use ParagonIE\ConstantTime\Base64;
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
    $decoded = base64_decode(b64url2b64($base64url), true);
    if ($decoded === false) {
        throw new \RuntimeException("Could not decode string as base64.");
    }
    return $decoded;
}

/**
 * Per RFC4648, "base64 encoding with URL-safe and filename-safe
 * alphabet".  This just replaces characters 62 and 63.  None of the
 * reference implementations seem to restore the padding if necessary,
 * but we'll do it anyway.
 * @param string $base64url
 * @return string
 */
function b64url2b64(string $base64url): string {
    // "Shouldn't" be necessary, but why not
    $padding = strlen($base64url) % 4;
    if ($padding > 0) {
        $base64url .= str_repeat('=', 4 - $padding);
    }
    return strtr($base64url, '-_', '+/');
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
     * @param string $password Not used, only public key supported
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

        return compact('curve', 'QA');
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
    private $providerConfig = array();

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
     * @var string if we acquire an access token it will be stored here
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
    private $scopes = array();

    /**
     * @var int|null Response code from the server
     */
    private $responseCode;

    /**
     * @var array holds response types
     */
    private $responseTypes = array();

    /**
     * @var array holds a cache of info returned from the user info endpoint
     */
    private $userInfo = array();

    /**
     * @var array holds authentication parameters
     */
    private $authParams = array();

    /**
     * @var array holds additional registration parameters for example post_logout_redirect_uris
     */
    private $registrationParams = array();

    /**
     * @var mixed holds well-known openid server properties
     */
    private $wellKnown = false;

    /**
     * @var mixed holds well-known opendid configuration parameters, like policy for MS Azure AD B2C User Flow  
     * @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/user-flow-overview 
     */
    private $wellKnownConfigParameters = array();

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
    private $additionalJwks = array();

    /**
     * @var object holds verified jwt claims
     */
    protected $verifiedClaims;

    /**
     * @var callable validator function for issuer claim
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
    private $pkceAlgs = array('S256' => 'sha256', 'plain' => false);

    /**
     * How long should be stored key in apcu cache in seconds
     * @var int
     */
    private $keyCacheExpiration = 3600;

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

    public function setProviderURL(string $provider_url)
    {
        $this->providerConfig['providerUrl'] = $provider_url;
    }

    public function setIssuer(string $issuer)
    {
        $this->providerConfig['issuer'] = $issuer;
    }

    public function setResponseTypes($response_types) {
        $this->responseTypes = array_merge($this->responseTypes, (array)$response_types);
    }

    /**
     * @return bool
     * @throws OpenIDConnectClientException
     */
    public function authenticate(): bool {

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect
        if (isset($_REQUEST['error'])) {
            $desc = isset($_REQUEST['error_description']) ? ' Description: ' . $_REQUEST['error_description'] : '';
            throw new OpenIDConnectClientException('Error: ' . $_REQUEST['error'] .$desc);
        }

        // If we have an authorization code then proceed to request a token
        if (isset($_REQUEST['code'])) {

            $code = $_REQUEST['code'];
            $token_json = $this->requestTokens($code);

            // Throw an error if the server returns one
            if (isset($token_json->error)) {
                if (isset($token_json->error_description)) {
                    throw new OpenIDConnectClientException($token_json->error_description);
                }
                throw new OpenIDConnectClientException('Got response: ' . $token_json->error);
            }

            // Do an OpenID Connect session check
            if ($_REQUEST['state'] !== $this->getState()) {
                throw new OpenIDConnectClientException('Unable to determine state');
            }

            // Cleanup state
            $this->unsetState();

            if (!property_exists($token_json, 'id_token')) {
                throw new OpenIDConnectClientException('User did not authorize openid scope.');
            }

            $claims = $this->decodeJWT($token_json->id_token, 1);

            // Verify the signature
            if (!$this->verifyJWTsignature($token_json->id_token)) {
                throw new OpenIDConnectClientException ('Unable to verify signature');
            }

            // Save the id token
            $this->idToken = $token_json->id_token;

            // Save the access token
            $this->accessToken = $token_json->access_token;

            // If this is a valid claim
            if ($this->verifyJWTclaims($claims, $token_json->access_token)) {

                // Clean up the session a little
                $this->unsetNonce();

                // Save the full response
                $this->tokenResponse = $token_json;

                // Save the verified claims
                $this->verifiedClaims = $claims;

                // Save the refresh token, if we got one
                if (isset($token_json->refresh_token)) {
                    $this->refreshToken = $token_json->refresh_token;
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
            if ($_REQUEST['state'] !== $this->getState()) {
                throw new OpenIDConnectClientException('Unable to determine state');
            }

            // Cleanup state
            $this->unsetState();

            $claims = $this->decodeJWT($id_token, 1);

            // Verify the signature
            if (!$this->verifyJWTsignature($id_token)) {
                throw new OpenIDConnectClientException ('Unable to verify signature');
            }

            // Save the id token
            $this->idToken = $id_token;

            // If this is a valid claim
            if ($this->verifyJWTclaims($claims, $accessToken)) {

                // Clean up the session a little
                $this->unsetNonce();

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
     * @param array $scope - example: openid, given_name, etc...
     */
    public function addScope($scope) {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    /**
     * @param array $param - example: prompt=login
     */
    public function addAuthParam($param) {
        $this->authParams = array_merge($this->authParams, (array)$param);
    }

    /**
     * @param array $param - example: post_logout_redirect_uris=[http://example.com/successful-logout]
     */
    public function addRegistrationParam($param) {
        $this->registrationParams = array_merge($this->registrationParams, (array)$param);
    }

    /**
     * @param object $jwk - example: (object) array('kid' => ..., 'nbf' => ..., 'use' => 'sig', 'kty' => "RSA", 'e' => "", 'n' => "")
     */
    protected function addAdditionalJwk($jwk) {
        $this->additionalJwks[] = $jwk;
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param string $param
     * @param mixed|null $default
     * @throws OpenIDConnectClientException
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
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param string $param
     * @param mixed|null $default optional
     * @throws OpenIDConnectClientException
     * @return mixed
     */
    private function getWellKnownConfigValue(string $param, $default = null)
    {
        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if (!$this->wellKnown) {
            if (str_ends_with($this->getProviderURL(), '/.well-known/openid-configuration')) {
                $wellKnownConfigUrl = $this->getProviderURL();
            } else {
                $wellKnownConfigUrl = rtrim($this->getProviderURL(), '/') . '/.well-known/openid-configuration';
            }

            if (!empty($this->wellKnownConfigParameters)) {
                $wellKnownConfigUrl .= '?' .  http_build_query($this->wellKnownConfigParameters);
            }
            $this->wellKnown = $this->jsonDecode($this->fetchURL($wellKnownConfigUrl));
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
    public function setWellKnownConfigParameters(array $params = []){
        $this->wellKnownConfigParameters=$params;
    }


    /**
     * @param string $url Sets redirect URL for auth flow
     */
    public function setRedirectURL(string $url) {
        if (parse_url($url,PHP_URL_HOST) !== false) {
            $this->redirectURL = $url;
        }
    }

    /**
     * Gets the URL of the current page we are on, encodes, and returns it
     *
     * @return string
     */
    public function getRedirectURL() {

        // If the redirect URL has been set then return it.
        if (property_exists($this, 'redirectURL') && $this->redirectURL) {
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

        if ($this->httpUpgradeInsecureRequests && isset($_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS']) && ($_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'] === '1')) {
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
            $port = intval($_SERVER['HTTP_X_FORWARDED_PORT']);
        } elseif (isset($_SERVER['SERVER_PORT'])) {
            $port = intval($_SERVER['SERVER_PORT']);
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

        $port = (443 === $port) || (80 === $port) ? '' : ':' . $port;
	    
        $explodedRequestUri = isset($_SERVER['REQUEST_URI']) ? explode('?', $_SERVER['REQUEST_URI']) : [];
        return sprintf('%s://%s%s/%s', $protocol, $host, $port, trim(reset($explodedRequestUri), '/'));
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
     * @throws \Exception
     */
    private function requestAuthorization()
    {
        $auth_endpoint = $this->getProviderConfigValue('authorization_endpoint');

        // Generate and store a nonce in the session
        // The nonce is an arbitrary value
        $nonce = $this->generateRandString();
        $this->setNonce($nonce);

        // State essentially acts as a session key for OIDC
        $state = $this->generateRandString();
        $this->setState($state);

        $auth_params = array_merge($this->authParams, array(
            'response_type' => 'code',
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'nonce' => $nonce,
            'state' => $state,
            'scope' => 'openid'
        ));

        // If the client has been registered with additional scopes
        if (!empty($this->scopes)) {
            $auth_params['scope'] = implode(' ', array_merge($this->scopes, ['openid']));
        }

        // If the client has been registered with additional response types
        if (!empty($this->responseTypes)) {
            $auth_params['response_type'] = implode(' ', $this->responseTypes);
        }

        // If the client supports Proof Key for Code Exchange (PKCE)
        $ccm = $this->getCodeChallengeMethod();
        if (!empty($ccm) && in_array($this->getCodeChallengeMethod(), $this->getProviderConfigValue('code_challenge_methods_supported'))) {
            $codeVerifier = bin2hex(random_bytes(64));
            $this->setCodeVerifier($codeVerifier);
            if (!empty($this->pkceAlgs[$this->getCodeChallengeMethod()])) {
                $codeChallenge = rtrim(strtr(base64_encode(hash($this->pkceAlgs[$this->getCodeChallengeMethod()], $codeVerifier, true)), '+/', '-_'), '=');
            } else {
                $codeChallenge = $codeVerifier;
            }
            $auth_params = array_merge($auth_params, array(
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => $this->getCodeChallengeMethod()
            ));
        }

        $auth_endpoint .= (strpos($auth_endpoint, '?') === false ? '?' : '&') . http_build_query($auth_params, '', '&', $this->enc_type);

        $this->commitSession();
        $this->redirect($auth_endpoint);
    }

    /**
     * Requests a client credentials token
     *
     * @throws OpenIDConnectClientException
     */
    public function requestClientCredentialsToken() {
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
     */
    public function requestResourceOwnerToken($bClientAuth = FALSE) {
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
     * @return mixed
     * @throws OpenIDConnectClientException
     */
    protected function requestTokens(string $code) {
        $token_endpoint = $this->getProviderConfigValue('token_endpoint');
        $token_endpoint_auth_methods_supported = $this->getProviderConfigValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);

        $headers = [];

        $grant_type = 'authorization_code';

        $token_params = array(
            'grant_type' => $grant_type,
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret
        );

        # Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported, true)) {
            $headers = ['Authorization: Basic ' . base64_encode(urlencode($this->clientID) . ':' . urlencode($this->clientSecret))];
            unset($token_params['client_secret']);
	        unset($token_params['client_id']);
        }

        $ccm = $this->getCodeChallengeMethod();
        $cv = $this->getCodeVerifier();
        if (!empty($ccm) && !empty($cv)) {
            $headers = [];
            unset($token_params['client_secret']);
            $token_params = array_merge($token_params, array(
                'client_id' => $this->clientID,
                'code_verifier' => $this->getCodeVerifier()
            ));
        }

        // Convert token params to string format
        $token_params = http_build_query($token_params, '', '&', $this->enc_type);

        $this->tokenResponse = json_decode($this->fetchURL($token_endpoint, $token_params, $headers));

        return $this->tokenResponse;
    }

    /**
     * Requests Access token with refresh token
     *
     * @param string $refresh_token
     * @return mixed
     * @throws OpenIDConnectClientException
     */
    public function refreshToken($refresh_token) {
        $token_endpoint = $this->getProviderConfigValue('token_endpoint');
        $token_endpoint_auth_methods_supported = $this->getProviderConfigValue('token_endpoint_auth_methods_supported', ['client_secret_basic']);

        $headers = [];

        $grant_type = 'refresh_token';

        $token_params = array(
            'grant_type' => $grant_type,
            'refresh_token' => $refresh_token,
            'client_id' => $this->clientID,
            'client_secret' => $this->clientSecret,
            'scope'         => implode(' ', $this->scopes),
        );

        # Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported, true)) {
            $headers = ['Authorization: Basic ' . base64_encode(urlencode($this->clientID) . ':' . urlencode($this->clientSecret))];
            unset($token_params['client_secret']);
            unset($token_params['client_id']);
        }

        // Convert token params to string format
        $token_params = http_build_query($token_params, '', '&', $this->enc_type);

        $json = json_decode($this->fetchURL($token_endpoint, $token_params, $headers));

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

            $modulus = new BigInteger(Base64::decode(b64url2b64($key->n)), 256);
            $exponent = new BigInteger(Base64::decode(b64url2b64($key->e)), 256);
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
     */
    private function fetchKeyForHeader($header, string $type): AsymmetricKey
    {
        $jwksUri = $this->getProviderConfigValue('jwks_uri');
        if (!$jwksUri) {
            throw new OpenIDConnectClientException ('Unable to verify signature due to no jwks_uri being defined');
        }

        if (function_exists('apcu_fetch') && $this->keyCacheExpiration > 0) {
            $cacheKey = 'openid_connect_' . md5($jwksUri);
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
     * @param string $hashtype
     * @param RSA $key
     * @param string $payload
     * @param string $signature
     * @param bool $isPss
     * @return bool
     * @throws OpenIDConnectClientException
     */
    private function verifyRSAJWTsignature(string $hashtype, RSA $key, string $payload, string $signature, bool $isPss): bool
    {
        $rsa = $key
            ->withHash($hashtype);
        if ($isPss) {
            $rsa = $rsa->withMGFHash($hashtype)
                ->withPadding(RSA::SIGNATURE_PSS);
        } else {
            $rsa = $rsa->withPadding(RSA::SIGNATURE_PKCS1);
        }
        return $rsa->verify($payload, $signature);
    }

    /**
     * @param string $hashtype
     * @param string $key
     * @param string $payload
     * @param string $signature
     * @return bool
     * @throws OpenIDConnectClientException
     */
    private function verifyHMACJWTsignature(string $hashtype, string $key, string $payload, string $signature): bool
    {
        if (!function_exists('hash_hmac')) {
            throw new OpenIDConnectClientException('hash_hmac support unavailable.');
        }

        $expected = hash_hmac($hashtype, $payload, $key, true);

        return hash_equals($signature, $expected);
    }

    /**
     * @param string $hashtype
     * @param EC $ec
     * @param string $payload
     * @param string $signature
     * @return bool
     * @throws OpenIDConnectClientException
     */
    private function verifyEcJwtSignature(string $hashtype, EC $ec, string $payload, string $signature): bool
    {
        $half = strlen($signature) / 2;
        if (!is_int($half)) {
            throw new OpenIDConnectClientException("Signature has invalid length");
        }
        $rawSignature = [
            'r' => new BigInteger(substr($signature, 0, $half), 256),
            's' => new BigInteger(substr($signature, $half), 256),
        ];
        return $ec->withSignatureFormat('raw')->withHash($hashtype)->verify($payload, $rawSignature);
    }

    /**
     * @param string $jwt encoded JWT
     * @throws OpenIDConnectClientException
     * @return bool
     */
    public function verifyJWTsignature(string $jwt): bool
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
                return $this->verifyRSAJWTsignature($hashType, $key, $payload, $signature, $isPss);
            case 'HS256':
            case 'HS512':
            case 'HS384':
                $hashType = 'SHA' . substr($header->alg, 2);
                return $this->verifyHMACJWTsignature($hashType, $this->getClientSecret(), $payload, $signature);
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
     */
    protected function verifyJWTclaims($claims, string $accessToken = null): bool
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

        if (isset($claims->nonce) && $claims->nonce !== $this->getNonce()) {
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
     * @return object
     */
    protected function decodeJWT(string $jwt, int $section = 0) {

        $parts = explode('.', $jwt);
        return json_decode(base64url_decode($parts[$section]));
    }

    /**
     *
     * @param string|null $attribute optional
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
     * locale           string      The End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Implementations MAY choose to accept this locale syntax as well.
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

        $userInfoEndpoint = $this->getProviderConfigValue('userinfo_endpoint');
        $userInfoEndpoint .= '?schema=openid';

        // The accessToken has to be sent in the Authorization header.
        // Accept json to indicate response type
        $headers = [
            "Authorization: Bearer {$this->accessToken}",
            'Accept: application/json',
        ];

        $userInfo = $this->jsonDecode($this->fetchURL($userInfoEndpoint,null, $headers));
        if ($this->getResponseCode() <> 200) {
            throw new OpenIDConnectClientException('The communication to retrieve user data has failed with status code ' . $this->getResponseCode());
        }
        $this->userInfo = $userInfo;

        if ($attribute === null) {
            return $this->userInfo;
        }

        if (property_exists($this->userInfo, $attribute)) {
            return $this->userInfo->$attribute;
        }

        return null;
    }

    /**
     *
     * @param string|null $attribute optional
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
     * auth_time        int     Authenatication time
     * oid              string  Object id
     *
     * @return mixed
     *
     */
    public function getVerifiedClaims(string $attribute = null) {

        if($attribute === null) {
            return $this->verifiedClaims;
        }

        if (property_exists($this->verifiedClaims, $attribute)) {
            return $this->verifiedClaims->$attribute;
        }

        return null;
    }

    /**
     * @param string $url
     * @param string | null $post_body string If this is set the post type will be POST
     * @param array $headers Extra headers to be send with the request. Format as 'NameHeader: ValueHeader'
     * @throws OpenIDConnectClientException
     * @return mixed
     */
    protected function fetchURL(string $url, $post_body = null, array $headers = array()) {


        // OK cool - then let's create a new cURL resource handle
        $ch = curl_init();

        // Determine whether this is a GET or POST
        if ($post_body !== null) {
            // curl_setopt($ch, CURLOPT_POST, 1);
            // Alows to keep the POST method even after redirect
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);

            // Default content type is form encoded
            $content_type = 'application/x-www-form-urlencoded';

            // Determine if this is a JSON payload and add the appropriate content type
            if (is_object(json_decode($post_body))) {
                $content_type = 'application/json';
            }

            // Add POST-specific headers
            $headers[] = "Content-Type: {$content_type}";

        }

        // If we set some headers include them
        if(count($headers) > 0) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        // Set URL to download
        curl_setopt($ch, CURLOPT_URL, $url);

        if (isset($this->httpProxy)) {
            curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
        }

        // Include header in result? (0 = yes, 1 = no)
        curl_setopt($ch, CURLOPT_HEADER, 0);

        // Allows to follow redirect
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        /**
         * Set cert
         * Otherwise ignore SSL peer verification
         */
        if (isset($this->certPath)) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->certPath);
        }

        if($this->verifyHost) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }

        if($this->verifyPeer) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        } else {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        }

        // Should cURL return or print out the data? (true = return, false = print)
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // Timeout in seconds
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeOut);

        // Download the given URL, and return output
        $output = curl_exec($ch);

        // HTTP Response code from server may be required from subclass
        $info = curl_getinfo($ch);
        $this->responseCode = $info['http_code'];

        if ($output === false) {
            throw new OpenIDConnectClientException('Curl error: (' . curl_errno($ch) . ') ' . curl_error($ch));
        }

        // Close the cURL resource, and free system resources
        curl_close($ch);

        return $output;
    }

    /**
     * @param bool $appendSlash
     * @return string
     * @throws OpenIDConnectClientException
     */
    public function getWellKnownIssuer(bool $appendSlash = false) {

        return $this->getWellKnownConfigValue('issuer') . ($appendSlash ? '/' : '');
    }

    /**
     * @return string
     * @throws OpenIDConnectClientException
     */
    public function getIssuer() {

        if (!isset($this->providerConfig['issuer'])) {
            throw new OpenIDConnectClientException('The issuer has not been set');
        }

        return $this->providerConfig['issuer'];
    }

    /**
     * @return mixed
     * @throws OpenIDConnectClientException
     */
    public function getProviderURL() {
        if (!isset($this->providerConfig['providerUrl'])) {
            throw new OpenIDConnectClientException('The provider URL has not been set');
        }

        return $this->providerConfig['providerUrl'];
    }

    /**
     * @param string $url
     */
    public function redirect(string $url) {
        header('Location: ' . $url);
        exit;
    }

    /**
     * @param string|null $httpProxy
     */
    public function setHttpProxy(string $httpProxy) {
        $this->httpProxy = $httpProxy;
    }

    /**
     * @param string $certPath
     */
    public function setCertPath(string $certPath) {
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
    public function setVerifyPeer(bool $verifyPeer) {
        $this->verifyPeer = $verifyPeer;
    }

    /**
     * @param bool $verifyHost
     */
    public function setVerifyHost(bool $verifyHost) {
        $this->verifyHost = $verifyHost;
    }


    /**
     * Controls whether http header HTTP_UPGRADE_INSECURE_REQUESTS should be considered
     * defaults to true
     * @param bool $httpUpgradeInsecureRequests
     */
    public function setHttpUpgradeInsecureRequests(bool $httpUpgradeInsecureRequests) {
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
     * @param callable $issuerValidator
     */
    public function setIssuerValidator(callable $issuerValidator)
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
     *
     * Use this to alter a provider's endpoints and other attributes
     *
     * @param array $array
     *        simple key => value
     */
    public function providerConfigParam(array $array) {
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
     * @return string
     */
    public function getClientName() {
        return $this->clientName;
    }

    /**
     * @param string $clientName
     */
    public function setClientName(string $clientName) {
        $this->clientName = $clientName;
    }

    /**
     * @return string
     */
    public function getClientID() {
        return $this->clientID;
    }

    /**
     * @return string
     */
    public function getClientSecret() {
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
    public function setAccessToken(string  $accessToken) {
        $this->accessToken = $accessToken;
    }

    /**
     * @return string
     */
    public function getAccessToken() {
        return $this->accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken() {
        return $this->refreshToken;
    }

    /**
     * @return string
     */
    public function getIdToken() {
        return $this->idToken;
    }

    /**
     * @return object
     */
    public function getAccessTokenHeader() {
        return $this->decodeJWT($this->accessToken);
    }

    /**
     * @return object
     */
    public function getAccessTokenPayload() {
        return $this->decodeJWT($this->accessToken, 1);
    }

    /**
     * @return object
     */
    public function getIdTokenHeader() {
        return $this->decodeJWT($this->idToken);
    }

    /**
     * @return object
     */
    public function getIdTokenPayload() {
        return $this->decodeJWT($this->idToken, 1);
    }

    /**
     * @return \stdClass
     */
    public function getTokenResponse() {
        return $this->tokenResponse;
    }

    /**
     * Stores nonce
     *
     * @param string $nonce
     * @return string
     */
    protected function setNonce(string $nonce) {
        $this->setSessionKey('openid_connect_nonce', $nonce);
        return $nonce;
    }

    /**
     * Get stored nonce
     *
     * @return string
     */
    protected function getNonce() {
        return $this->getSessionKey('openid_connect_nonce');
    }

    /**
     * Cleanup nonce
     *
     * @return void
     */
    protected function unsetNonce() {
        $this->unsetSessionKey('openid_connect_nonce');
    }

    /**
     * Stores $state
     *
     * @param string $state
     * @return string
     */
    protected function setState(string $state) {
        $this->setSessionKey('openid_connect_state', $state);
        return $state;
    }

    /**
     * Get stored state
     *
     * @return string
     */
    protected function getState() {
        return $this->getSessionKey('openid_connect_state');
    }

    /**
     * Cleanup state
     *
     * @return void
     */
    protected function unsetState() {
        $this->unsetSessionKey('openid_connect_state');
    }

    /**
     * Stores $codeVerifier
     *
     * @param string $codeVerifier
     * @return string
     */
    protected function setCodeVerifier($codeVerifier) {
        $this->setSessionKey('openid_connect_code_verifier', $codeVerifier);
        return $codeVerifier;
    }

    /**
     * Get stored codeVerifier
     *
     * @return string
     */
    protected function getCodeVerifier() {
        return $this->getSessionKey('openid_connect_code_verifier');
    }

    /**
     * Cleanup state
     *
     * @return void
     */
    protected function unsetCodeVerifier() {
        $this->unsetSessionKey('openid_connect_code_verifier');
    }

    /**
     * Get the response code from last action/curl request.
     *
     * @return int
     */
    public function getResponseCode()
    {
        return $this->responseCode;
    }

    /**
     * Set timeout (seconds)
     *
     * @param int $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeOut = $timeout;
    }

    /**
     * @return int
     */
    public function getTimeout()
    {
        return $this->timeOut;
    }

    /**
     * Use session to manage a nonce
     */
    protected function startSession() {
        if (!isset($_SESSION)) {
            @session_start();
        }
    }

    protected function commitSession() {
        $this->startSession();

        session_write_close();
    }

    protected function getSessionKey($key) {
        $this->startSession();

        if (array_key_exists($key, $_SESSION)) {
            return $_SESSION[$key];
        }
        return false;
    }

    protected function setSessionKey($key, $value) {
        $this->startSession();

        $_SESSION[$key] = $value;
    }

    protected function unsetSessionKey($key) {
        $this->startSession();

        unset($_SESSION[$key]);
    }

    public function setUrlEncoding(int $curEncoding)
    {
        switch ($curEncoding)
        {
            case PHP_QUERY_RFC1738:
                $this->enc_type = PHP_QUERY_RFC1738;
                break;

            case PHP_QUERY_RFC3986:
                $this->enc_type = PHP_QUERY_RFC3986;
                break;

        	default:
                break;
        }

    }

    /**
     * @return array
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * @return array
     */
    public function getResponseTypes()
    {
        return $this->responseTypes;
    }

    /**
     * @return array
     */
    public function getAuthParams()
    {
        return $this->authParams;
    }

    /**
     * @return callable
     */
    public function getIssuerValidator()
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
     * @return string
     */
    public function getCodeChallengeMethod() {
        return $this->codeChallengeMethod;
    }

    /**
     * @param string $codeChallengeMethod
     */
    public function setCodeChallengeMethod(string $codeChallengeMethod) {
        $this->codeChallengeMethod = $codeChallengeMethod;
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
}
