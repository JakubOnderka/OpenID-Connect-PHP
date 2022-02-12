<?php

// phpcs:disable PSR1.Classes.ClassDeclaration.MultipleClasses
// phpcs:disable PSR12.Properties.ConstantVisibility.NotFound
// phpcs:disable Generic.Files.LineLength.TooLong
/**
 * Copyright MITRE 2020
 * Copyright Jakub Onderka 2022
 *
 * OpenIDConnectClient for PHP7
 * Author: Michael Jett <mjett@mitre.org>
 *         Jakub Onderka <jakub.onderka@gmail.com>
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
 */

declare(strict_types=1);

namespace JakubOnderka;

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
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
function base64url_decode(string $base64url): string
{
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
function base64url_encode(string $str): string
{
    $enc = base64_encode($str);
    $enc = rtrim($enc, '=');
    $enc = strtr($enc, '+/', '-_');
    return $enc;
}

class JsonException extends \Exception
{
}

class Json
{
    /**
     * @param string $json
     * @param bool $mustBeObject Check that decoded JSON is an object
     * @return \stdClass|mixed
     * @throws JsonException
     */
    public static function decode(string $json, $mustBeObject = true)
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
        if ($mustBeObject && !$decoded instanceof \stdClass) {
            throw new JsonException("Decoded JSON must be object, " . gettype($decoded) . " type received.");
        }
        return $decoded;
    }

    /**
     * @param mixed $value
     * @return string
     * @throws JsonException
     */
    public static function encode($value): string
    {
        if (defined('JSON_THROW_ON_ERROR')) {
            try {
                return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            } catch (\JsonException $e) {
                throw new JsonException("Could not encode provided value", 0, $e);
            }
        }

        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($encoded === false) {
            throw new JsonException("Could not encode provided value: " . json_last_error_msg());
        }
        return $encoded;
    }
}

/**
 * OpenIDConnect Exception Class
 */
class OpenIDConnectClientException extends \Exception
{
}

class TokenValidationFailed extends \Exception
{
    /**
     * @param string $message
     * @param mixed|null $expected
     * @param mixed|null $actual
     */
    public function __construct(string $message = "", $expected = null, $actual = null)
    {
        if ($expected !== null) {
            $message .= " (expected: `$expected`, actual: `$actual`)";
        }
        parent::__construct($message);
    }
}

/**
 * Error Response from section 5.2 of RFC 6749
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
class ErrorResponse extends OpenIDConnectClientException
{
    /** @var string */
    private $error;

    public function __construct(string $error, string $description = null, \Throwable $previous = null)
    {
        $this->error = $error;

        $message = "Error '$error' received from IdP";
        if ($description) {
            $message .= ': ' . $description;
        }
        parent::__construct($message, 0, $previous);
    }

    public function getError(): string
    {
        return $this->error;
    }
}

class CurlResponse
{
    /** @var string */
    public $data;

    /** @var int */
    public $responseCode;

    /** @var string|null */
    public $contentType;

    public function __construct(string $data, int $responseCode = 200, string $contentType = null)
    {
        $this->data = $data;
        $this->responseCode = $responseCode;
        $this->contentType = $contentType;
    }

    /**
     * @param bool $mustBeObject Check that decoded JSON is an object
     * @return \stdClass|mixed
     * @throws JsonException
     */
    public function json(bool $mustBeObject = false)
    {
        return Json::decode($this->data, $mustBeObject);
    }

    /**
     * @return bool Returns true if response code is between 200-299
     */
    public function isSuccess(): bool
    {
        return $this->responseCode >= 200 && $this->responseCode < 300;
    }
}

/**
 * JSON Web Key Set
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 */
class Jwks implements \JsonSerializable
{
    /**
     * @var array<\stdClass>
     */
    private $keys;

    /**
     * @param array<\stdClass> $keys
     */
    public function __construct(array $keys = [])
    {
        $this->keys = $keys;
    }

    /**
     * @param PublicKey $publicKey
     * @param string|null $kid
     * @param string|null $use Can be 'sig' for signing or 'enc' for encryption
     * @return void
     */
    public function addPublicKey(PublicKey $publicKey, string $kid = null, string $use = null)
    {
        if ($publicKey instanceof EC\PublicKey) {
            switch ($publicKey->getCurve()) {
                case 'secp256r1':
                    $output = $this->generateSecpCurveObject($publicKey, 'P-256', 'ES256');
                    break;
                case 'secp384r1':
                    $output = $this->generateSecpCurveObject($publicKey, 'P-384', 'ES384');
                    break;
                case 'secp521r1':
                    $output = $this->generateSecpCurveObject($publicKey, 'P-521', 'ES512');
                    break;
                case 'Ed25519':
                case 'Ed448':
                    $output = $this->generateEdCurveObject($publicKey);
                    break;
                default:
                    throw new \InvalidArgumentException("Unsupported curve {$publicKey->getCurve()}");
            }
        } elseif ($publicKey instanceof RSA\PublicKey) {
            /** @var array $raw */
            $raw = $publicKey->toString('raw');
            $output = [
                'kty' => 'RSA',
                'n' => base64url_encode($raw['n']->toBytes()),
                'e' => base64url_encode($raw['e']->toBytes()),
            ];
        } else {
            throw new \InvalidArgumentException("Unsupported public key type " . get_class($publicKey));
        }

        if ($kid) {
            $output['kid'] = $kid;
        }
        if ($use) {
            $output['use'] = $use;
        }

        $this->keys[] = (object)$output;
    }

    private function generateSecpCurveObject(EC\PublicKey $publicKey, string $crv, string $alg): array
    {
        $coordinates = substr($publicKey->getEncodedCoordinates(), 1);
        $half = strlen($coordinates) / 2;

        return [
            'kty' => 'EC',
            'crv' => $crv,
            'alg' => $alg,
            'x' => base64url_encode(substr($coordinates, 0, $half)),
            'y' => base64url_encode(substr($coordinates, $half)),
        ];
    }

    private function generateEdCurveObject(EC\PublicKey $publicKey): array
    {
        return [
            'kty' => 'OKP',
            'crv' => $publicKey->getCurve(),
            'alg' => 'EdDSA',
            'x' => base64url_encode($publicKey->getEncodedCoordinates()),
        ];
    }

    /**
     * @throws OpenIDConnectClientException
     */
    public function getKeyForHeader(\stdClass $header): PublicKey
    {
        if (!isset($header->alg)) {
            throw new OpenIDConnectClientException("Malformed JWT token header, `alg` field is missing");
        }

        if ($header->alg === 'EdDSA') {
            $keyType = 'OKP';
        } else {
             $keyType = $header->alg[0] === 'E' ? 'EC' : 'RSA';
        }

        foreach ($this->keys as $key) {
            if ($key->kty === $keyType) {
                if (!isset($header->kid) || $key->kid === $header->kid) {
                    return $this->convertJwtToPublicKey($key);
                }
            } else {
                if (isset($key->alg) && isset($key->kid) && $key->alg === $header->alg && $key->kid === $header->kid) {
                    return $this->convertJwtToPublicKey($key);
                }
            }
        }
        if (isset($header->kid)) {
            throw new OpenIDConnectClientException("Unable to find a key for $header->alg with kid `$header->kid`");
        }
        throw new OpenIDConnectClientException("Unable to find a key for $keyType");
    }

    /**
     * @param \stdClass $key
     * @return PublicKey
     * @throws OpenIDConnectClientException
     */
    private function convertJwtToPublicKey(\stdClass $key): PublicKey
    {
        if (!isset($key->kty)) {
            throw new OpenIDConnectClientException("Malformed key object, `kty` field is missing");
        }

        if ($key->kty === 'EC') {
            if (!isset($key->x) || !isset($key->y) || !isset($key->crv)) {
                throw new OpenIDConnectClientException('Malformed EC key object');
            }

            EC::addFileFormat(JwkEcFormat::class);
            return EC::loadPublicKey($key);
        } elseif ($key->kty === 'OKP') {
            if (!isset($key->x) || !isset($key->crv)) {
                throw new OpenIDConnectClientException('Malformed OKP key object');
            }

            EC::addFileFormat(JwkEcFormat::class);
            return EC::loadPublicKey($key);
        } elseif ($key->kty === 'RSA') {
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
            return RSA::loadPublicKey($publicKeyRaw);
        }
        throw new OpenIDConnectClientException("Not supported key type $key->kty");
    }

    /**
     * Remove unnecessary part of keys when storing in cache
     * @return string[]
     */
    public function __sleep()
    {
        foreach ($this->keys as $key) {
            unset($key->x5c);
            unset($key->x5t);
            unset($key->{'x5t#S256'});
        }
        return ['keys'];
    }

    /**
     * @return array[]
     */
    public function jsonSerialize(): array
    {
        return ['keys' => $this->keys];
    }
}

abstract class JwkEcFormat
{
    use EC\Formats\Keys\Common;

    /**
     * @param mixed $key
     * @param string|null $password Not used, only public key supported
     * @return array{"curve": EC\BaseCurves\Base, "QA": array}|false
     * @throws \RuntimeException
     */
    public static function load($key, $password)
    {
        if (!is_object($key)) {
            return false;
        }

        $curve = self::getCurve($key->crv);

        if ($curve instanceof EC\BaseCurves\TwistedEdwards) {
            $QA = self::extractPoint(base64url_decode($key->x), $curve);
            return ['curve' => $curve, 'QA' => $QA];
        }

        /** @var EC\BaseCurves\Prime  $curve */
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
    private static function getCurve(string $curveName): EC\BaseCurves\Base
    {
        switch ($curveName) {
            case 'P-256':
                return new Curves\nistp256();
            case 'P-384':
                return new Curves\nistp384();
            case 'P-521':
                return new Curves\nistp521();
            case 'Ed25519':
                return new Curves\Ed25519();
            case 'Ed448':
                return new Curves\Ed448();
        }
        throw new \RuntimeException("Unsupported curve $curveName");
    }
}

class Jwt
{
    const SUPPORTED_ALGOS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];

    /** @var string */
    private $token;

    /**
     * Holds parsed payload
     * @var \stdClass
     */
    private $payloadCache;

    public function __construct(string $token)
    {
        if (substr_count($token, '.') !== 2) {
            throw new \InvalidArgumentException("Token is not valid signed JWT (JWS), it must contains three parts separated by dots");
        }
        $this->token = $token;
    }

    /**
     * JOSE header
     * @throws JsonException
     * @throws \Exception
     */
    public function header(): \stdClass
    {
        $headerPart = strstr($this->token, '.', true);
        return Json::decode(base64url_decode($headerPart));
    }

    /**
     * @return \stdClass
     * @throws JsonException
     * @throws \Exception
     */
    public function payload(): \stdClass
    {
        if ($this->payloadCache) {
            return $this->payloadCache;
        }

        $start = strpos($this->token, '.') + 1;
        $end = strpos($this->token, '.', $start);
        $this->payloadCache = Json::decode(base64url_decode(substr($this->token, $start, $end - $start)));
        return $this->payloadCache;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function signature(): string
    {
        $signaturePart = strrchr($this->token, ".");
        return base64url_decode(substr($signaturePart, 1));
    }

    /**
     * @return string
     */
    public function withoutSignature(): string
    {
        return substr($this->token, 0, strrpos($this->token, '.'));
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->token;
    }

    /**
     * Check signature of this JWT.
     *
     * @param \Closure(\stdClass): mixed|string|PublicKey $key Closure that accepts parsed header and returns appropriate key
     * @throws JsonException
     * @throws \Exception
     */
    public function verify($key): bool
    {
        $signature = $this->signature();
        if ('' === $signature) {
            throw new \RuntimeException('Decoded signature is empty string');
        }

        $header = $this->header();
        if (!isset($header->alg)) {
            throw new \RuntimeException('Error missing signature type in token header');
        }

        if (!in_array($header->alg, self::SUPPORTED_ALGOS, true)) {
            throw new \RuntimeException("Unsupported JWT signature algorith $header->alg");
        }

        if ($key instanceof \Closure) {
            $key = $key($header);
        }

        $payload = $this->withoutSignature();

        switch ($header->alg[0]) {
            case 'H':
                $hashType = 'sha' . substr($header->alg, 2);
                return $this->verifyHmacSignature($hashType, $key, $payload, $signature);
            case 'R':
            case 'P':
                $hashType = 'sha' . substr($header->alg, 2);
                $isPss = $header->alg[0] === 'P';
                return $this->verifyRsaSignature($hashType, $key, $payload, $signature, $isPss);
            default: // ES or EdDSA
                return $this->verifyEcSignature($header->alg, $key, $payload, $signature);
        }
    }

    private function verifyHmacSignature(string $hashType, string $key, string $payload, string $signature): bool
    {
        $expected = hash_hmac($hashType, $payload, $key, true);
        return hash_equals($signature, $expected);
    }

    private function verifyRsaSignature(string $hashType, RSA\PublicKey $key, string $payload, string $signature, bool $isPss): bool
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

    private function verifyEcSignature(string $alg, EC\PublicKey $key, string $payload, string $signature): bool
    {
        switch ($alg) {
            case 'ES256':
                $requiredCurve = 'secp256r1';
                $expectedHalfSignatureSize = 32;
                $hashType = 'sha256';
                break;
            case 'ES384':
                $requiredCurve = 'secp384r1';
                $expectedHalfSignatureSize = 48;
                $hashType = 'sha384';
                break;
            case 'ES512':
                $requiredCurve = 'secp521r1';
                $expectedHalfSignatureSize = 66;
                $hashType = 'sha512';
                break;
            default: // EdDSA
                if (!in_array($key->getCurve(), ['Ed25519', 'Ed448'], true)) {
                    throw new \RuntimeException("Invalid curve {$key->getCurve()} provided for verifying EdDSA signed token");
                }
                return $key->verify($payload, $signature);
        }

        if ($key->getCurve() !== $requiredCurve) {
            throw new \RuntimeException("Invalid curve {$key->getCurve()} provided for verifying $alg signed token ($requiredCurve curve is required)");
        }

        $half = strlen($signature) / 2;
        if ($expectedHalfSignatureSize !== $half) {
            throw new \RuntimeException("Signature has invalid length, expected $expectedHalfSignatureSize bytes, got $half");
        }
        $rawSignature = [
            'r' => new BigInteger(substr($signature, 0, $half), 256),
            's' => new BigInteger(substr($signature, $half), 256),
        ];
        return $key->withSignatureFormat('raw')->withHash($hashType)->verify($payload, $rawSignature);
    }

    /**
     * Create JWT signed by provided shared secret
     *
     * @param array<string, mixed> $payload
     * @param string $hashAlg
     * @param string $secret
     * @return Jwt
     * @throws JsonException
     */
    public static function createHmacSigned(array $payload, string $hashAlg, string $secret): Jwt
    {
        if (!in_array($hashAlg, ['HS256', 'HS384', 'HS512'], true)) {
            throw new \InvalidArgumentException("Invalid JWT signature algorithm $hashAlg");
        }

        $headerAndPayload = self::createHeaderAndPayload($payload, $hashAlg);
        $hmac = hash_hmac('sha' . substr($hashAlg, 2), $headerAndPayload, $secret, true);
        $signature = base64url_encode($hmac);
        return new Jwt("$headerAndPayload.$signature");
    }

    /**
     * Create JWT signed by provided private elliptic curve private key. Algo will be chosen according to private key size.
     *
     * @param array $payload
     * @param EC\PrivateKey $privateKey
     * @param string|null $kid
     * @return Jwt
     * @throws JsonException
     */
    public static function createEcSigned(array $payload, EC\PrivateKey $privateKey, string $kid = null): Jwt
    {
        switch ($privateKey->getCurve()) {
            case 'secp256r1':
                $hashType = 'sha256';
                $alg = 'ES256';
                $expectedHalfSignatureSize = 32;
                break;
            case 'secp384r1':
                $hashType = 'sha384';
                $alg = 'ES384';
                $expectedHalfSignatureSize = 48;
                break;
            case 'secp521r1':
                $hashType = 'sha512';
                $alg = 'ES512';
                $expectedHalfSignatureSize = 66;
                break;
            case 'Ed25519':
                $hashType = 'sha512';
                $alg = 'EdDSA';
                break;
            case 'Ed448':
                $hashType = 'shake256-912';
                $alg = 'EdDSA';
                break;
            default:
                throw new \InvalidArgumentException("Unsupported curve {$privateKey->getCurve()}");
        }

        $headerAndPayload = self::createHeaderAndPayload($payload, $alg, $kid);

        $signature = $privateKey
            ->withHash($hashType)
            ->withSignatureFormat('raw')
            ->sign($headerAndPayload);

        // secp curves signature result is array
        if (isset($expectedHalfSignatureSize)) {
            // From RFC 7518: Turn R and S into octet sequences in big-endian order, with each array being be 32 octets long.
            // The octet sequence representations MUST NOT be shortened to omit any leading zero octets contained in the values.
            $r = str_pad($signature['r']->toBytes(), $expectedHalfSignatureSize, "\0", STR_PAD_LEFT);
            $s = str_pad($signature['s']->toBytes(), $expectedHalfSignatureSize, "\0", STR_PAD_LEFT);
            $signature = $r . $s;
        }
        $signature = base64url_encode($signature);
        return new Jwt("$headerAndPayload.$signature");
    }

    /**
     * Create JWT signed by provided private RSA (RS* or PS* algos).
     *
     * @param array $payload
     * @param string $alg
     * @param RSA\PrivateKey $privateKey
     * @param string|null $kid Key ID
     * @return Jwt
     * @throws JsonException
     */
    public static function createRsaSigned(array $payload, string $alg, RSA\PrivateKey $privateKey, string $kid = null): Jwt
    {
        if (!in_array($alg, ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'], true)) {
            throw new \InvalidArgumentException("Invalid JWT signature algorithm $alg");
        }

        $headerAndPayload = self::createHeaderAndPayload($payload, $alg, $kid);

        $hashType = 'sha' . substr($alg, 2, 3);
        $privateKey = $privateKey->withHash($hashType);

        $isPss = $alg[0] === 'P';
        if ($isPss) {
            $privateKey = $privateKey->withMGFHash($hashType)
                ->withPadding(RSA::SIGNATURE_PSS);
        } else {
            $privateKey = $privateKey->withPadding(RSA::SIGNATURE_PKCS1);
        }
        $signature = $privateKey->sign($headerAndPayload);

        $signature = base64url_encode($signature);
        return new Jwt("$headerAndPayload.$signature");
    }

    /**
     * @param array $payload
     * @param string $alg
     * @param string|null $kid
     * @return string
     * @throws JsonException
     */
    private static function createHeaderAndPayload(array $payload, string $alg, string $kid = null): string
    {
        if ($kid) {
            $header = '{"alg":"' . $alg . '","typ":"JWT","kid":' . Json::encode($kid) . '}';
        } else {
            $header = '{"alg":"' . $alg . '","typ":"JWT"}';
        }

        $header = base64url_encode($header);
        $payload = base64url_encode(Json::encode($payload));
        return "$header.$payload";
    }
}

class OpenIDConnectClient
{
    // In seconds
    const IAT_SLACK = 600;

    // Session keys
    const NONCE = 'openid_connect_nonce',
        STATE = 'openid_connect_state',
        CODE_VERIFIER = 'openid_connect_code_verifier';

    // APCu cache keys
    const KEYS_CACHE = 'openid_connect_key_',
        WELLKNOWN_CACHE = 'openid_connect_wellknown_',
        LOGOUT_JTI = 'openid_connect_logout_jti_';

    /**
     * @var string
     */
    private $providerUrl;

    /**
     * @var string arbitrary id value
     */
    private $clientID;

    /**
     * @var string arbitrary secret value
     */
    private $clientSecret;

    /**
     * @var PrivateKey|null
     */
    private $clientPrivateKey;

    /**
     * @var array<string, mixed> holds the provider configuration
     */
    private $providerConfig = [];

    /**
     * @var string|null http proxy if necessary
     */
    private $httpProxy;

    /**
     * Full system path to the SSL/TLS public certificate, that will be used to validate remote server certificates.
     * When not set, system certificates will be used. Makes sense just when `verifyPeer` is set to true.
     * @var string|null
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
     * @var string|null if we acquire an access token it will be stored here. Access token can be any string.
     */
    protected $accessToken;

    /**
     * @var string|null if we acquire a refresh token it will be stored here
     */
    private $refreshToken;

    /**
     * @var Jwt|null if we acquire an id token it will be stored here
     */
    protected $idToken;

    /**
     * @var \stdClass stores the token response
     */
    private $tokenResponse;

    /**
     * @var array<string> holds scopes
     */
    private $scopes = [];

    /**
     * @var array<string> holds response types
     * @see https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
     */
    private $responseTypes = [];

    /**
     * @var \stdClass|null holds a cache of info returned from the user info endpoint
     */
    private $userInfo;

    /**
     * @var array<string, mixed> holds authentication parameters
     */
    private $authParams = [];

    /**
     * @var array<string, mixed> holds additional registration parameters for example post_logout_redirect_uris
     */
    private $registrationParams = [];

    /**
     * @var \stdClass holds well-known openid server properties
     */
    private $wellKnown;

    /**
     * @var array holds well-known opendid configuration parameters, like policy for MS Azure AD B2C User Flow
     * @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/user-flow-overview
     */
    private $wellKnownConfigParameters = [];

    /**
     * Remote requests timeout in seconds
     * @var int
     */
    protected $timeOut = 60;

    /**
     * @var Jwks|null
     */
    private $jwks;

    /**
     * @var Jwks|null holds response types
     */
    private $additionalJwks;

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
    protected $encType = PHP_QUERY_RFC1738;

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
     * @var array<string, mixed> holds PKCE supported algorithms
     */
    const PKCE_ALGS = ['S256' => 'sha256', 'plain' => false];

    /**
     * How long should be stored wellknown JSON in apcu cache in seconds. Use zero to disable caching.
     * @var int
     */
    private $wellknownCacheExpiration = 86400; // one day

    /**
     * How long should be stored key in apcu cache in seconds. Use zero to disable caching.
     * @var int
     */
    private $keyCacheExpiration = 86400; // one day

    /**
     * @var resource|\CurlHandle|null CURL handle
     */
    private $ch;

    /**
     * @var string|null
     */
    private $authenticationMethod;

    /**
     * @param string $providerUrl
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @param string|null $issuer An Issuer Identifier is a case sensitive URL. If not provided, $providerUrl will be used as issuer
     * @throws OpenIDConnectClientException
     */
    public function __construct(string $providerUrl, string $clientId = null, string $clientSecret = null, string $issuer = null)
    {
        // Require the cURL and JSON PHP extensions to be installed
        if (!function_exists('curl_init')) {
            throw new OpenIDConnectClientException('OpenIDConnectClient requires the cURL PHP extension.');
        }
        if (!function_exists('json_decode')) {
            throw new OpenIDConnectClientException('OpenIDConnectClient requires the JSON PHP extension.');
        }

        $this->setProviderURL($providerUrl);
        $this->setIssuer($issuer ?: $this->getProviderURL());

        $this->clientID = $clientId;
        $this->clientSecret = $clientSecret;

        $this->issuerValidator = function (string $iss): bool {
            $iss = rtrim($iss, '/'); // normalize
            return $iss === rtrim($this->getIssuer(), '/') || $iss === rtrim($this->getWellKnownIssuer(), '/');
        };
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
            $tokenJson = $this->requestTokens($_REQUEST['code']);

            $this->validateStateFromSession();

            if (!isset($tokenJson->id_token)) {
                throw new OpenIDConnectClientException('User did not authorize openid scope.');
            }

            // Save the id token
            $this->idToken = new Jwt($tokenJson->id_token);

            // Verify the signature
            if (!$this->verifyJwtSignature($this->idToken)) {
                throw new OpenIDConnectClientException('Unable to verify signature of ID token');
            }

            // Save the access token
            $this->accessToken = $tokenJson->access_token;

            // If this is a valid claim
            try {
                $this->validateIdToken($this->idToken, $tokenJson->access_token);
            } catch (TokenValidationFailed $e) {
                throw new OpenIDConnectClientException('Unable to validate ID token claims', 0, $e);
            } finally {
                // Remove nonce from session to avoid replay attacks
                $this->unsetSessionKey(self::NONCE);
            }

            // Save the full response
            $this->tokenResponse = $tokenJson;

            // Save the refresh token, if we got one
            if (isset($tokenJson->refresh_token)) {
                $this->refreshToken = $tokenJson->refresh_token;
            }

            // Success!
            return true;
        }

        if ($this->allowImplicitFlow && isset($_REQUEST['id_token'])) {
            // if we have no code but an id_token use that
            $idToken = $_REQUEST['id_token'];

            $accessToken = null;
            if (isset($_REQUEST['access_token'])) {
                $accessToken = $_REQUEST['access_token'];
            }

            $this->validateStateFromSession();

            // Verify the signature
            if (!$this->verifyJwtSignature($idToken)) {
                throw new OpenIDConnectClientException('Unable to verify ID token signature');
            }

            // Save the id token
            $this->idToken = new Jwt($idToken);

            // If this is a valid claim
            try {
                $this->validateIdToken($this->idToken, $accessToken);
            } catch (TokenValidationFailed $e) {
                throw new OpenIDConnectClientException('Unable to validate ID token claims', 0, $e);
            } finally {
                // Remove nonce from session to avoid replay attacks
                $this->unsetSessionKey(self::NONCE);
            }

            // Save the access token
            if ($accessToken) {
                $this->accessToken = $accessToken;
            }

            // Success!
            return true;
        }

        $this->requestAuthorization();
        return false; // this should never happen
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
     * @returns void
     * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function signOut(string $idToken, string $redirect = null)
    {
        $signoutParams = ['id_token_hint' => $idToken];
        if ($redirect !== null) {
            $signoutParams['post_logout_redirect_uri'] = $redirect;
        }

        $this->redirectToEndpoint('end_session_endpoint', $signoutParams);
    }

    /**
     * @param array|string $scope - example: openid, given_name, etc...
     * @retutn void
     */
    public function addScope($scope)
    {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    /**
     * @param array<string, mixed> $param - example: prompt=login
     */
    public function addAuthParam(array $param)
    {
        $this->authParams = array_merge($this->authParams, $param);
    }

    /**
     * @param array<string, mixed> $param - example: post_logout_redirect_uris=[http://example.com/successful-logout]
     * @return void
     */
    public function addRegistrationParam(array $param)
    {
        $this->registrationParams = array_merge($this->registrationParams, $param);
    }

    /**
     * Add additional JSON Web Key, that will append to keys fetched from remote server
     * @param Jwks $jwks
     */
    protected function setAdditionalJwks(Jwks $jwks)
    {
        $this->additionalJwks = $jwks;
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param string $param
     * @param mixed|null $default
     * @return mixed
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    protected function getProviderConfigValue(string $param, $default = null)
    {
        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        return $this->providerConfig[$param] ?? $this->getWellKnownConfigValue($param, $default);
    }

    /**
     * @param \stdClass $metadata
     * @return void
     * @throws OpenIDConnectClientException
     */
    private function validateMetadataIssuer(\stdClass $metadata)
    {
        if (!isset($metadata->issuer)) {
            throw new OpenIDConnectClientException("Invalid OpenID Provider Metadata returned, they do not contain required `issuer` field.");
        }

        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
        // The issuer value returned MUST be identical to the Issuer URL that was directly used to retrieve the configuration information.
        // Strip last `/` to normalize responses
        $expectedIssuer = rtrim($this->getIssuer(), '/');
        $actualIssuer = rtrim($metadata->issuer, '/');

        if ($actualIssuer !== $expectedIssuer) {
            throw new OpenIDConnectClientException("Invalid OpenID Provider Metadata returned, expected issuer `$expectedIssuer`, `$actualIssuer` provided.");
        }
    }

    /**
     * @return \stdClass
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    private function fetchProviderMetadata(): \stdClass
    {
        $wellKnownConfigUrl = rtrim($this->getProviderURL(), '/') . '/.well-known/openid-configuration';

        if (!empty($this->wellKnownConfigParameters)) {
            $wellKnownConfigUrl .= '?' . http_build_query($this->wellKnownConfigParameters);
        }

        if ($this->wellknownCacheExpiration && function_exists('apcu_fetch')) {
            $metadata = apcu_fetch(self::WELLKNOWN_CACHE . md5($wellKnownConfigUrl));
            if ($metadata) {
                // Just for sure also validate metadata from cache
                $this->validateMetadataIssuer($metadata);
                return $metadata;
            }
        }

        $response = $this->fetchURL($wellKnownConfigUrl);
        if (!$response->isSuccess()) {
            throw new OpenIDConnectClientException("Invalid response code $response->responseCode when fetching wellKnow, expected 200");
        }
        $metadata = $response->json(true);

        $this->validateMetadataIssuer($metadata);

        if ($this->wellknownCacheExpiration && function_exists('apcu_store')) {
            apcu_store(self::WELLKNOWN_CACHE . md5($wellKnownConfigUrl), $metadata, $this->wellknownCacheExpiration);
        }

        return $metadata;
    }

    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param string $param
     * @param mixed|null $default Default value that will be used when $param is not found
     * @return mixed
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    private function getWellKnownConfigValue(string $param, $default = null)
    {
        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if (!$this->wellKnown) {
            $this->wellKnown = $this->fetchProviderMetadata();
        }

        if (isset($this->wellKnown->{$param})) {
            return $this->wellKnown->{$param};
        }

        if ($default !== null) {
            // Uses default value if provided
            return $default;
        }

        throw new OpenIDConnectClientException("The provider `$param` is not available in metadata.");
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
     * @return void
     * @throw \InvalidArgumentException if invalid URL specified
     */
    public function setRedirectURL(string $url)
    {
        if (!parse_url($url, PHP_URL_HOST)) {
            throw new \InvalidArgumentException("Invalid redirect URL provided");
        }
        $this->redirectURL = $url;
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
     * Start Here
     * @return void
     * @throws OpenIDConnectClientException
     * @throws JsonException
     * @throws \Exception
     */
    private function requestAuthorization()
    {
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
        $ccm = $this->codeChallengeMethod;
        if ($ccm) {
            $supportedCodeChallengeMethods = $this->getProviderConfigValue('code_challenge_methods_supported', []);
            if (!in_array($ccm, $supportedCodeChallengeMethods, true)) {
                throw new OpenIDConnectClientException("Unsupported code challenge method $ccm by IdP. Supported methods: " . implode(', ', $supportedCodeChallengeMethods));
            }

            $codeVerifier = base64url_encode(\random_bytes(32));
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

        // Send as signed JWT to remote server when client secret or private key is set
        // @see https://datatracker.ietf.org/doc/html/rfc9101
        if ($this->getProviderConfigValue('request_parameter_supported', false) && ($this->clientPrivateKey || $this->clientSecret)) {
            if ($this->clientPrivateKey instanceof EC\PrivateKey) {
                $jwt = Jwt::createEcSigned($authParams, $this->clientPrivateKey);
            } elseif ($this->clientPrivateKey) {
                $jwt = Jwt::createRsaSigned($authParams, 'RS256', $this->clientPrivateKey);
            } else {
                $jwt = Jwt::createHmacSigned($authParams, 'HS256', $this->clientSecret);
            }
            // Values for the response_type and client_id parameters MUST be included using the OAuth 2.0 request syntax,
            // since they are REQUIRED by OAuth 2.0
            $authParams = [
                'request' => (string)$jwt,
                'client_id' => $this->clientID,
                'scope' => $authParams['scope'],
            ];
            if (!empty($this->responseTypes)) {
                $authParams['response_type'] = implode(' ', $this->responseTypes);
            }
        }

        // PAR, @see https://datatracker.ietf.org/doc/html/rfc9126
        if ($this->getProviderConfigValue('pushed_authorization_request_endpoint', false)) {
            $response = $this->endpointRequest($authParams, 'pushed_authorization_request');
            if (isset($response->request_uri)) {
                $authParams = [
                    'client_id' => $this->clientID,
                    'request_uri' => $response->request_uri,
                ];
            }
        }

        $this->commitSession();
        $this->redirectToEndpoint('authorization_endpoint', $authParams);
    }

    /**
     * Requests a client credentials token
     *
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function requestClientCredentialsToken(): \stdClass
    {
        $postData = [
            'grant_type' => 'client_credentials',
        ];
        if (!empty($this->scopes)) {
            $postData['scope'] = implode(' ', $this->scopes);
        }

        return $this->endpointRequest($postData);
    }

    /**
     * Requests a resource owner token
     * (Defined in https://tools.ietf.org/html/rfc6749#section-4.3)
     *
     * @param boolean $bClientAuth Indicates that the Client ID and Secret be used for client authentication
     * @return \stdClass
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function requestResourceOwnerToken(bool $bClientAuth = false): \stdClass
    {
        $postData = [
            'grant_type' => 'password',
            'username' => $this->authParams['username'],
            'password' => $this->authParams['password'],
            'scope' => implode(' ', $this->scopes)
        ];

        // For client authentication include the client values
        if ($bClientAuth) {
            return $this->endpointRequest($postData);
        }

        $token_endpoint = $this->getProviderConfigValue('token_endpoint');
        return $this->fetchURL($token_endpoint, $postData)->json(true);
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
        $tokenParams = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->getRedirectURL(),
        ];

        if ($this->codeChallengeMethod) {
            $cv = $this->getSessionKey(self::CODE_VERIFIER);
            if (empty($cv)) {
                throw new OpenIDConnectClientException("Code verifier from session is empty");
            }

            $tokenParams = array_merge($tokenParams, [
                'client_id' => $this->clientID,
                'code_verifier' => $cv,
            ]);
        }

        if ($this->allowImplicitFlow) {
            // For implicit flow, we don't have client secret required for authentication
            $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');
            $response = $this->fetchURL($tokenEndpoint, $tokenParams)->json(true);

            if (isset($response->error)) {
                // @phpstan-ignore-next-line phpstan bug #6026
                throw new ErrorResponse($response->error, $response->error_description ?? null);
            }
            return $response;
        }

        return $this->endpointRequest($tokenParams);
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
        $tokenParams = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'scope' => implode(' ', $this->scopes),
        ];

        $json = $this->endpointRequest($tokenParams);

        if (isset($json->access_token)) {
            $this->accessToken = $json->access_token;
        }

        if (isset($json->refresh_token)) {
            $this->refreshToken = $json->refresh_token;
        }

        return $json;
    }

    /**
     * @param \stdClass $header
     * @return PublicKey
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    private function fetchKeyForHeader(\stdClass $header): PublicKey
    {
        if ($this->jwks) {
            try {
                return $this->jwks->getKeyForHeader($header);
            } catch (\Exception $e) {
                // ignore if key not found and fetch key from server again
            }
        }

        $jwksUri = $this->getProviderConfigValue('jwks_uri');
        if (!$jwksUri) {
            throw new OpenIDConnectClientException('Unable to verify signature due to no jwks_uri being defined');
        }

        if (function_exists('apcu_fetch') && $this->keyCacheExpiration > 0) {
            $cacheKey = self::KEYS_CACHE . md5($jwksUri);
            /** @var Jwks|false $jwks */
            $jwks = apcu_fetch($cacheKey);
            if ($jwks) {
                $this->jwks = $jwks;
                try {
                    return $jwks->getKeyForHeader($header);
                } catch (\Exception $e) {
                    // ignore if key not found and fetch key from server again
                }
            }
        }

        try {
            $response = $this->fetchURL($jwksUri);
            if (!$response->isSuccess()) {
                throw new \Exception("Invalid response code $response->responseCode.");
            }
            $jwks = $this->jwks = new Jwks($response->json(true)->keys);
        } catch (\Exception $e) {
            throw new OpenIDConnectClientException('Error fetching JSON from jwks_uri', 0, $e);
        }

        if (isset($cacheKey)) {
            apcu_store($cacheKey, $jwks, $this->keyCacheExpiration);
        }

        try {
            return $jwks->getKeyForHeader($header);
        } catch (OpenIDConnectClientException $e) {
            // No key found, try to check additionalJwks as last option
            if ($this->additionalJwks) {
                return $this->additionalJwks->getKeyForHeader($header);
            } else {
                throw $e;
            }
        }
    }

    /**
     * @param Jwt $jwt
     * @return bool
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function verifyJwtSignature(Jwt $jwt): bool
    {
        return $jwt->verify(function (\stdClass $header) {
            if ($header->alg[0] === 'H') {
                if (!isset($this->clientSecret)) {
                    throw new OpenIDConnectClientException("Token is signed by client secret, but client secret not provided.");
                }
                return $this->clientSecret;
            } else {
                return $this->fetchKeyForHeader($header);
            }
        });
    }

    /**
     * Validate ID token and access token if provided.
     *
     * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
     * @param Jwt $jwt
     * @param string|null $accessToken If access token is provided, it will be validate if match to ID token
     * @return void
     * @throws OpenIDConnectClientException
     * @throws JsonException
     * @throws TokenValidationFailed
     */
    protected function validateIdToken(Jwt $jwt, string $accessToken = null)
    {
        $claims = $jwt->payload();

        // (2). The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience.
        if (!isset($claims->iss)) {
            throw new TokenValidationFailed("Required `iss` claim not provided");
        } elseif (!($this->issuerValidator)($claims->iss)) {
            throw new TokenValidationFailed("It didn't pass issuer validator", $this->getIssuer(), $claims->iss);
        }

        if (!isset($claims->sub)) {
            throw new TokenValidationFailed("Required `sub` claim not provided");
        }

        // (3). Audience
        if (!isset($claims->aud)) {
            throw new TokenValidationFailed("Required `aud` claim not provided");
        } elseif ($claims->aud !== $this->clientID && !in_array($this->clientID, (array)$claims->aud, true)) {
            throw new TokenValidationFailed("Client ID do not match to `aud` claim", $this->clientID, $claims->aud);
        }

        // (4). If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
        if (is_array($claims->aud) && count($claims->aud) > 1 && !isset($claims->azp)) {
            throw new TokenValidationFailed("Multiple audiences provided, but `azp` claim not provided");
        }

        // (5). If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
        if (isset($claims->azp) && $claims->azp !== $this->clientID) {
            throw new TokenValidationFailed("Client ID do not match to `azp` claim", $this->clientID, $claims->azp);
        }

        $time = time();

        // (9). Token expiration time
        if (!isset($claims->exp)) {
            throw new TokenValidationFailed("Required `exp` claim not provided");
        } elseif (!is_int($claims->exp) && !is_double($claims->exp)) {
            throw new TokenValidationFailed("Required `exp` claim provided, but type is incorrect", 'int', gettype($claims->exp));
        } elseif ($claims->exp < $time) {
            throw new TokenValidationFailed("Token is already expired, expired at " . date('c', $claims->exp));
        }

        // (10). Time at which the JWT was issued.
        $this->validateIat($claims, $time);

        // (11). If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value
        // checked to verify that it is the same value as the one that was sent in the Authentication Request.
        $sessionNonce = $this->getSessionKey(self::NONCE);
        if (!isset($claims->nonce)) {
            throw new TokenValidationFailed("Required `nonce` claim not provided");
        } elseif ($sessionNonce === null) {
            throw new TokenValidationFailed("Session nonce is not set");
        } elseif (!hash_equals($sessionNonce, $claims->nonce)) {
            throw new TokenValidationFailed("Nonce do not match", $sessionNonce, $claims->nonce);
        }

        // Access Token hash value. Its value is the base64url encoding of the left-most half of the hash of the octets
        // of the ASCII representation of the access_token value, where the hash algorithm used is the hash algorithm
        // used in the alg Header Parameter of the ID Token's JOSE Header.
        if (isset($claims->at_hash) && isset($accessToken)) {
            $idTokenHeader = $this->idToken->header();
            if (isset($idTokenHeader->alg) && $idTokenHeader->alg !== 'none') {
                $bit = substr($idTokenHeader->alg, 2, 3);
            } else {
                // This should never happened, because alg is already checked in verifyJwtSignature method
                throw new OpenIDConnectClientException("Invalid ID token alg");
            }
            $len = $bit / 16;
            $expectedAtHash = base64url_encode(substr(hash('sha' . $bit, $accessToken, true), 0, $len));

            if (!hash_equals($expectedAtHash, $claims->at_hash)) {
                throw new TokenValidationFailed("`at_hash` claim do not match to provided access token", $expectedAtHash, $claims->at_hash);
            }
        }
    }

    /**
     * Verify signature and validate claims of back channel logout token.
     *
     * @param Jwt $jwt
     * @return void
     * @throws JsonException
     * @throws OpenIDConnectClientException
     * @throws TokenValidationFailed
     */
    public function verifyAndValidateLogoutToken(Jwt $jwt)
    {
        $this->verifyJwtSignature($jwt);
        $this->validateLogoutToken($jwt);
    }

    /**
     * @return void
     * @throws TokenValidationFailed
     * @throws OpenIDConnectClientException
     * @throws JsonException
     * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
     */
    protected function validateLogoutToken(Jwt $jwt)
    {
        $claims = $jwt->payload();

        // (3). Validate the iss, aud, and iat Claims in the same way they are validated in ID Tokens.
        if (!isset($claims->iss)) {
            throw new TokenValidationFailed("Required `iss` claim not provided");
        } elseif (!($this->issuerValidator)($claims->iss)) {
            throw new TokenValidationFailed("It didn't pass issuer validator", $this->getIssuer(), $claims->iss);
        }

        if (!isset($claims->aud)) {
            throw new TokenValidationFailed("Required `aud` claim not provided");
        } elseif ($claims->aud !== $this->clientID && !in_array($this->clientID, (array)$claims->aud, true)) {
            throw new TokenValidationFailed("Client ID do not match to `aud` claim", $this->clientID, $claims->aud);
        }

        $this->validateIat($claims, time());

        // (4). Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
        if (!isset($claims->sub) && !isset($claims->sid)) {
            throw new TokenValidationFailed("Required `sub` or `sid` claim not provided");
        }

        // (5). Verify that the Logout Token contains an events Claim whose value is JSON object containing
        // the member name http://schemas.openid.net/event/backchannel-logout.
        if (!isset($claims->events)) {
            throw new TokenValidationFailed("Required `events` claim not provided");
        } elseif (!isset($claims->events->{'http://schemas.openid.net/event/backchannel-logout'})) {
            throw new TokenValidationFailed("`events` claim do not contains required member name");
        }

        // (6). Verify that the Logout Token does not contain a nonce Claim.
        if (isset($claims->nonce)) {
            throw new TokenValidationFailed("Prohibited `nonce` claim provided");
        }

        // (7). Optionally verify that another Logout Token with the same jti value has not been recently received.
        if (isset($claims->jti) && function_exists('apcu_exists')) {
            if (apcu_exists(self::LOGOUT_JTI . $claims->jti)) {
                throw new TokenValidationFailed("`jti` was recently used", null, $claims->jti);
            }
            apcu_store(self::LOGOUT_JTI . $claims->jti, true, self::IAT_SLACK * 2 + 5);
        }
    }

    /**
     * @param \stdClass $claims
     * @param int $time
     * @return void
     * @throws TokenValidationFailed
     */
    private function validateIat(\stdClass $claims, int $time)
    {
        $idTokenIatSlack = self::IAT_SLACK;
        if (!isset($claims->iat)) {
            throw new TokenValidationFailed("Required `iat` claim not provided");
        } elseif (!is_int($claims->iat) && !is_double($claims->iat)) {
            throw new TokenValidationFailed("Required `iat` claim provided, but type is incorrect", 'int', gettype($claims->iat));
        } elseif (($time - $idTokenIatSlack) > $claims->iat) {
            $issued = date('c', $claims->iat);
            throw new TokenValidationFailed("Token was issued at $issued, that is more than $idTokenIatSlack seconds ago");
        } elseif (($time + $idTokenIatSlack) < $claims->iat) {
            $issued = date('c', $claims->iat);
            throw new TokenValidationFailed("Token was issued at $issued, that is more than $idTokenIatSlack seconds in future");
        }
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
     * nickname         string      Casual name of the End-User that may or may not be the same as the given_name.
     *                              For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
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
     *                              For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US;
     *                              Implementations MAY choose to accept this locale syntax as well.
     * phone_number     string      The End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim. For example, +1 (425) 555-1212 or +56 (2) 687 2400.
     * address          JSON object The End-User's preferred address. The value of the address member is a JSON [RFC4627] structure containing some or all of the members defined in Section 2.4.2.1.
     * updated_time     string      Time the End-User's information was last updated, represented as a RFC 3339 [RFC3339] datetime. For example, 2011-01-03T23:58:42+0000.
     *
     * @return mixed|null Returns null when provided attribute doesn't exists.
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function requestUserInfo(string $attribute = null)
    {
        if (!$this->userInfo) {
            if (!isset($this->accessToken)) {
                throw new OpenIDConnectClientException("Access token is not defined");
            }

            if (!$this->getIdToken()) {
                throw new OpenIDConnectClientException("ID token is required for verifying that `sub` claim match when requesting userInfo");
            }

            $userInfoEndpoint = $this->getProviderConfigValue('userinfo_endpoint');
            $userInfoEndpoint .= '?schema=openid';

            // The accessToken has to be sent in the Authorization header.
            // Accept json to indicate response type
            $headers = [
                "Authorization: Bearer $this->accessToken",
                'Accept: application/json',
            ];

            $userInfo = $this->fetchJsonOrJwk($userInfoEndpoint, null, $headers);

            if (!isset($userInfo->sub)) {
                throw new OpenIDConnectClientException("Invalid user info returned, required `sub` claim not provided");
            }

            // The sub Claim in the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token;
            // if they do not match, the UserInfo Response values MUST NOT be used.
            if ($userInfo->sub !== $this->getIdToken()->payload()->sub) {
                throw new OpenIDConnectClientException("Invalid user info returned, `sub` claim doesn't match with `sub` claim from ID token");
            }

            $this->userInfo = $userInfo;
        }

        if ($attribute === null) {
            return $this->userInfo;
        }

        return $this->userInfo->$attribute ?? null;
    }

    /**
     * Get verified claims from ID token.
     *
     * These claims are defined by specification, but token can contain also other claims.
     *
     * Attribute        Type    Description
     * exp              int     REQUIRED Expires at
     * nbf              int     Not before
     * ver              string  Version
     * iss              string  REQUIRED Issuer
     * sub              string  REQUIRED Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User.
     * aud              string  REQUIRED Audience
     * nonce            string  nonce
     * iat              int     REQUIRED Issued At
     * auth_time        int     Authentication time
     * oid              string  Object id
     *
     * @param string|null $attribute If no attribute provided, all claims will be returned
     * @return mixed|null Returns null if provided attribute doesn't exists
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    public function getVerifiedClaims(string $attribute = null)
    {
        if (!$this->idToken) {
            throw new OpenIDConnectClientException("ID token is not set. Maybe user is not logged?");
        }

        $idTokenClaims = $this->idToken->payload();
        if ($attribute === null) {
            return $idTokenClaims;
        }

        return $idTokenClaims->$attribute ?? null;
    }

    /**
     * Fetch claim from ID token for current user. If claim doesn't exists in ID token,
     * this method tries to fetch claim from user info.
     *
     * @param string $attribute
     * @return mixed|null
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    public function getUserClaim(string $attribute)
    {
        $claim = $this->getVerifiedClaims($attribute);
        if ($claim !== null) {
            return $claim;
        }

        return $this->requestUserInfo($attribute);
    }

    /**
     * Dynamic Client Registration
     *
     * @see https://openid.net/specs/openid-connect-registration-1_0.html
     * @param string $clientName
     * @param string $authorization Authorization Bearer token
     * @return \stdClass Decoded response
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function register(string $clientName, string $authorization = null): \stdClass
    {
        $registrationEndpoint = $this->getProviderConfigValue('registration_endpoint');

        $postBody = array_merge($this->registrationParams, [
            'redirect_uris' => [$this->getRedirectURL()],
            'client_name' => $clientName,
        ]);

        $headers = ['Content-Type: application/json'];
        if ($authorization) {
            $headers[] = "Authorization: Bearer $authorization";
        }

        $response = $this->fetchURL($registrationEndpoint, Json::encode($postBody), $headers)->json(true);

        if (isset($response->error)) {
            // @phpstan-ignore-next-line phpstan bug #6026
            throw new ErrorResponse($response->error, $response->error_description ?? null);
        }

        return $response;
    }

    /**
     * Introspect a given token - either access token or refresh token.
     *
     * @see https://tools.ietf.org/html/rfc7662
     * @param string $token
     * @param string $tokenTypeHint Can be for example `access_token` or `refresh_token`
     * @return \stdClass
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function introspectToken(string $token, string $tokenTypeHint = null): \stdClass
    {
        $params = [
            'token' => $token,
        ];
        if ($tokenTypeHint) {
            $params['token_type_hint'] = $tokenTypeHint;
        }

        return $this->endpointRequest($params, 'introspection');
    }

    /**
     * Revoke a given token - either access token or refresh token. Return true if the token has been revoked
     * successfully or if the client submitted an invalid token.
     *
     * @see https://tools.ietf.org/html/rfc7009
     * @param string $token
     * @param string|null $tokenTypeHint Can be for example `access_token` or `refresh_token`
     * @return true
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function revokeToken(string $token, string $tokenTypeHint = null): bool
    {
        $params = [
            'token' => $token,
        ];
        if ($tokenTypeHint) {
            $params['token_type_hint'] = $tokenTypeHint;
        }

        $response = $this->endpointRequestRaw($params, 'revocation');
        if ($response->responseCode === 200) {
            return true;
        }
        $decoded = $response->json(true);
        if (isset($decoded->error)) {
            // @phpstan-ignore-next-line phpstan bug #6026
            throw new ErrorResponse($decoded->error, $decoded->error_description ?? null);
        }

        // invalid response
        throw new OpenIDConnectClientException($decoded);
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
    public function setAccessToken(string $accessToken)
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
     * @return Jwt|null
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @return \stdClass|null
     */
    public function getTokenResponse()
    {
        return $this->tokenResponse;
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
     * @return string
     * @throws OpenIDConnectClientException
     * @throws JsonException
     */
    public function getWellKnownIssuer(): string
    {
        return $this->getWellKnownConfigValue('issuer');
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
        if (!isset($this->providerUrl)) {
            throw new OpenIDConnectClientException('The provider URL has not been set');
        }
        return $this->providerUrl;
    }

    /**
     * @param string|null $httpProxy
     * @return void
     */
    public function setHttpProxy($httpProxy)
    {
        $this->httpProxy = $httpProxy;
    }

    /**
     * @param string $certPath
     * @return void
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
     * @return void
     */
    public function setVerifyPeer(bool $verifyPeer)
    {
        $this->verifyPeer = $verifyPeer;
    }

    /**
     * @param bool $verifyHost
     * @return void
     */
    public function setVerifyHost(bool $verifyHost)
    {
        $this->verifyHost = $verifyHost;
    }

    /**
     * Controls whether http header HTTP_UPGRADE_INSECURE_REQUESTS should be considered
     * defaults to true
     * @param bool $httpUpgradeInsecureRequests
     * @return void
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
     * @return void
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
     * @param array<string, mixed> $array
     *        simple key => value
     */
    public function providerConfigParam(array $array)
    {
        $this->providerConfig = array_merge($this->providerConfig, $array);
    }

    /**
     * @param string $clientSecret
     * @return void
     */
    public function setClientSecret(string $clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @param string $clientID
     * @return void
     */
    public function setClientID(string $clientID)
    {
        $this->clientID = $clientID;
    }

    /**
     * Set private key that will be used for authentication to identity provider. When key is set, authentication method
     * is automatically set to `private_key_jwt`.
     * @param PrivateKey $privateKey
     * @return void
     */
    public function setClientPrivateKey(PrivateKey $privateKey)
    {
        if ($privateKey instanceof EC\PrivateKey) {
            $supportedCurves = ['secp256r1', 'secp384r1', 'secp512r1', 'Ed22519', 'Ed448'];
            if (!in_array($privateKey->getCurve(), $supportedCurves, true)) {
                throw new \InvalidArgumentException("Unsupported EC curve {$privateKey->getCurve()} provided");
            }
        } elseif (!$privateKey instanceof RSA\PrivateKey) {
            throw new \InvalidArgumentException("Private key must be RSA or EC");
        }
        $this->setAuthenticationMethod('private_key_jwt');
        $this->clientPrivateKey = $privateKey;
    }

    /**
     * @param string $providerUrl
     * @return void
     */
    public function setProviderURL(string $providerUrl)
    {
        if (!filter_var($providerUrl, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Provider URL must be valid URL.");
        }

        // If provider already contains well-known part, we will strip it
        $wellKnownPart = strpos($providerUrl, '/.well-known/openid-configuration');
        if ($wellKnownPart !== false) {
            $providerUrl = substr($providerUrl, 0, $wellKnownPart + 1);
        }

        $this->providerUrl = $providerUrl;
    }

    /**
     * @param string $issuer
     * @return void
     */
    public function setIssuer(string $issuer)
    {
        if (!filter_var($issuer, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Issuer must be valid URL.");
        }

        $this->providerConfig['issuer'] = $issuer;
    }

    /**
     * @param string|array<string> $responseTypes
     * @return void
     */
    public function setResponseTypes($responseTypes)
    {
        $this->responseTypes = array_merge($this->responseTypes, (array)$responseTypes);
    }

    /**
     * @param int $urlEncoding PHP_QUERY_RFC1738 or PHP_QUERY_RFC3986 constant
     * @throws \InvalidArgumentException if unsupported URL encoding provided
     */
    public function setUrlEncoding(int $urlEncoding)
    {
        if (in_array($urlEncoding, [PHP_QUERY_RFC1738, PHP_QUERY_RFC3986], true)) {
            $this->encType = $urlEncoding;
        } else {
            throw new \InvalidArgumentException("Unsupported encoding provided");
        }
    }

    /**
     * @return array<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return array<string>
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
     * @param string|null $authenticationMethod
     * @return void
     */
    public function setAuthenticationMethod($authenticationMethod)
    {
        $supportedMethods = ['client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt'];
        if ($authenticationMethod !== null && !in_array($authenticationMethod, $supportedMethods, true)) {
            throw new \InvalidArgumentException("Unknown authentication method `$authenticationMethod` provided.");
        }

        $this->authenticationMethod = $authenticationMethod;
    }

    /**
     * @returns void
     * @throws OpenIDConnectClientException
     */
    public function validateStateFromSession()
    {
        if (!isset($_REQUEST['state'])) {
            throw new OpenIDConnectClientException('State not provided in request');
        }

        $stateFromSession = $this->getSessionKey(self::STATE);
        if ($stateFromSession === null) {
            throw new OpenIDConnectClientException('State is not set in session');
        }

        // Cleanup session state
        $this->unsetSessionKey(self::STATE);

        // Check if state from session and from request is the same
        if (!hash_equals($stateFromSession, $_REQUEST['state'])) {
            throw new OpenIDConnectClientException('State from session is different than provided state from request');
        }
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
        return $_SESSION[$key] ?? null;
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
     * @param string $url Must start with `http://` or `https://`
     * @param string|array|null $postBody string If this is set the post type will be POST
     * @param array<string> $headers Extra headers to be send with the request. Format as 'NameHeader: ValueHeader'
     * @return CurlResponse
     * @throws OpenIDConnectClientException
     */
    public function fetchURL(string $url, $postBody = null, array $headers = []): CurlResponse
    {
        if (!$this->ch) {
            // Share handle between requests to allow keep connection alive between requests
            $this->ch = curl_init();
            if (!$this->ch) {
                throw new \RuntimeException("Could not initialize cURL");
            }
        } else {
            // Reset options, so we can do another request
            curl_reset($this->ch);
        }

        $options = [
            CURLOPT_URL => $url, // Set URL to download
            CURLOPT_FOLLOWLOCATION => true, // Allows to follow redirect
            CURLOPT_SSL_VERIFYPEER => $this->verifyPeer,
            CURLOPT_SSL_VERIFYHOST => $this->verifyHost ? 2 : 0,
            CURLOPT_RETURNTRANSFER => true, // Should cURL return or print out the data? (true = return, false = print)
            CURLOPT_HEADER => false, // Include header in result?
            CURLOPT_TIMEOUT => $this->timeOut, // Timeout in seconds
            CURLOPT_USERAGENT => 'OpenIDConnectClient',
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP, // be sure that only HTTP and HTTPS protocols are enabled
        ];

        // If URL starts with https://, allow just to use HTTPS. This will also allows HTTPS only when following redirects
        if (strpos($url, 'https://') === 0) {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
        }

        // Determine whether this is a GET or POST
        if ($postBody !== null) {
            // Add the appropriate content type header if $postBody is array, for string request it is necessary to add
            // that content header by user
            if (is_array($postBody)) {
                $headers[] = "Content-Type: application/x-www-form-urlencoded";
                $postBody = http_build_query($postBody, '', '&', $this->encType);
            } elseif (!is_string($postBody)) {
                throw new \InvalidArgumentException("Invalid type for post body, expected array, string or null value");
            }

            // curl_setopt($this->ch, CURLOPT_POST, 1);
            // Allows to keep the POST method even after redirect
            $options[CURLOPT_CUSTOMREQUEST] = 'POST';
            $options[CURLOPT_POSTFIELDS] = $postBody;
        } else {
            // Enable response compression for GET requests
            $options[CURLOPT_ENCODING] = "";
        }

        // If we set some headers include them
        if (!empty($headers)) {
            $options[CURLOPT_HTTPHEADER] = $headers;
        }

        if (isset($this->httpProxy)) {
            $options[CURLOPT_PROXY] = $this->httpProxy;
        }

        if (isset($this->certPath)) {
            $options[CURLOPT_CAINFO] = $this->certPath;
        }

        if (!curl_setopt_array($this->ch, $options)) {
            throw new OpenIDConnectClientException('cURL error: Could not set options');
        }

        // Download the given URL, and return output
        $output = curl_exec($this->ch);

        if ($output === false) {
            throw new OpenIDConnectClientException('cURL error #' . curl_errno($this->ch) . ': ' . curl_error($this->ch));
        }

        $info = curl_getinfo($this->ch);

        return new CurlResponse($output, $info['http_code'], $info['content_type']);
    }

    /**
     * @param string $url
     * @param string|array|null $postBody
     * @param array<string> $headers
     * @return \stdClass
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    protected function fetchJsonOrJwk(string $url, $postBody = null, array $headers = []): \stdClass
    {
        $response = $this->fetchURL($url, $postBody, $headers);
        if (!$response->isSuccess()) {
            throw new OpenIDConnectClientException("Could not fetch $url, error code $response->responseCode");
        }
        if ($response->contentType === 'application/jwt') {
            $jwt = new Jwt($response->data);
            if (!$this->verifyJwtSignature($jwt)) {
                throw new OpenIDConnectClientException('Unable to verify signature');
            }
            return $jwt->payload();
        }
        return $response->json(true);
    }

    /**
     * @param array<string, mixed> $params
     * @param string $endpointName without `_endpoint`
     * @return CurlResponse
     * @throws JsonException
     * @throws OpenIDConnectClientException
     * @throws \Exception
     */
    protected function endpointRequestRaw(array $params, string $endpointName): CurlResponse
    {
        if (!in_array($endpointName, ['token', 'introspection', 'pushed_authorization_request', 'revocation'], true)) {
            throw new \InvalidArgumentException("Invalid endpoint name provided");
        }

        if (empty($this->clientID)) {
            throw new OpenIDConnectClientException("Client ID is required, but not set");
        }

        $endpoint = $this->getProviderConfigValue("{$endpointName}_endpoint");

        /*
         * Pushed Authorization Request endpoint uses the same auth methods as token endpoint.
         *
         * From RFC: Similarly, the token_endpoint_auth_methods_supported authorization server metadata parameter lists
         * client authentication methods supported by the authorization server when accepting direct requests from clients,
         * including requests to the PAR endpoint.
         */
        if ($endpointName === 'pushed_authorization_request') {
            $endpointName = 'token';
        }
        $authMethodsSupported = $this->getProviderConfigValue("{$endpointName}_endpoint_auth_methods_supported", ['client_secret_basic']);

        if ($this->authenticationMethod && !in_array($this->authenticationMethod, $authMethodsSupported)) {
            $supportedMethods = implode(", ", $authMethodsSupported);
            throw new OpenIDConnectClientException("Authentication method $this->authenticationMethod is not supported by IdP for $endpointName endpoint. Supported methods are: $supportedMethods");
        }

        $headers = ['Accept: application/json'];

        // See https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
        if ($this->authenticationMethod === 'client_secret_jwt' || $this->authenticationMethod === 'private_key_jwt') {
            $time = time();
            $tokenPayload = [
                'iss' => $this->clientID,
                'sub' => $this->clientID,
                'aud' => $this->getProviderConfigValue("token_endpoint"), // audience should be all the time token_endpoint
                'jti' => $this->generateRandString(),
                'exp' => $time + $this->timeOut,
                'iat' => $time,
            ];

            if ($this->authenticationMethod === 'private_key_jwt') {
                if (!$this->clientPrivateKey) {
                    throw new OpenIDConnectClientException("Authentication method is set to `private_key_jwt`, but private key is not set");
                }
                if ($this->clientPrivateKey instanceof EC\PrivateKey) {
                    $jwt = Jwt::createEcSigned($tokenPayload, $this->clientPrivateKey);
                } elseif ($this->clientPrivateKey instanceof RSA\PrivateKey) {
                    $jwt = Jwt::createRsaSigned($tokenPayload, 'RS256', $this->clientPrivateKey);
                } else {
                    throw new OpenIDConnectClientException("Invalid private key provided");
                }
            } else {
                if (!$this->clientSecret) {
                    throw new OpenIDConnectClientException("Authentication method is set to `client_secret_jwt`, but client secret is not set");
                }
                $jwt = Jwt::createHmacSigned($tokenPayload, 'HS256', $this->clientSecret);
            }

            $params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
            $params['client_assertion'] = (string)$jwt;
        } elseif (in_array('client_secret_basic', $authMethodsSupported, true) && $this->authenticationMethod !== 'client_secret_post') {
            $headers = ['Authorization: Basic ' . base64_encode(urlencode($this->clientID) . ':' . urlencode($this->clientSecret))];
        } else { // client_secret_post fallback
            $params['client_id'] = $this->clientID;
            $params['client_secret'] = $this->clientSecret;
        }
        return $this->fetchURL($endpoint, $params, $headers);
    }

    /**
     * @param array<string, mixed> $params
     * @param string $endpointName without `_endpoint`
     * @return \stdClass
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    protected function endpointRequest(array $params, string $endpointName = 'token'): \stdClass
    {
        $response = $this->endpointRequestRaw($params, $endpointName)->json(true);
        if (isset($response->error)) {
            // @phpstan-ignore-next-line phpstan bug #6026
            throw new ErrorResponse($response->error, $response->error_description ?? null);
        }
        return $response;
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
     * Redirect to given endpoint and params and exit
     *
     * @param string $endpointName
     * @param array $params
     * @return void
     * @throws JsonException
     * @throws OpenIDConnectClientException
     */
    protected function redirectToEndpoint(string $endpointName, array $params)
    {
        $url = $this->getProviderConfigValue($endpointName);
        $url .= strpos($url, '?') === false ? '?' : '&';
        $url .= http_build_query($params, '', '&', $this->encType);
        $this->redirect($url);
    }

    /**
     * @param string $url
     * @return void
     */
    protected function redirect(string $url)
    {
        header('Location: ' . $url);
        exit;
    }
}
