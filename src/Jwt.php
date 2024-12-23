<?php

declare(strict_types=1);

namespace JakubOnderka\OpenIDConnectClient;

use JakubOnderka\Json;
use JakubOnderka\JsonException;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Math\BigInteger;
use function JakubOnderka\base64url_decode;
use function JakubOnderka\base64url_encode;

class Jwt
{
    // Supported signature algorithms
    const SUPPORTED_ALGOS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];

    // List of elliptic curves supported for ES or EdDSA
    const SUPPORTED_CURVES = ['secp256r1', 'secp384r1', 'secp512r1', 'Ed22519', 'Ed448'];

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
    public static function createEcSigned(array $payload, EC\PrivateKey $privateKey, ?string $kid = null): Jwt
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
    public static function createRsaSigned(array $payload, string $alg, RSA\PrivateKey $privateKey, ?string $kid = null): Jwt
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
    private static function createHeaderAndPayload(array $payload, string $alg, ?string $kid = null): string
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
