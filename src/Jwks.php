<?php

// phpcs:disable PSR1.Classes.ClassDeclaration.MultipleClasses

declare(strict_types=1);

namespace JakubOnderka\OpenIDConnectClient;

use JakubOnderka\OpenIDConnectClientException;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Curves;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use function JakubOnderka\base64url_decode;
use function JakubOnderka\base64url_encode;

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
    public function addPublicKey(PublicKey $publicKey, ?string $kid = null, ?string $use = null)
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

    /**
     * Find appropriate public key that was used for JWT signature.
     * @throws OpenIDConnectClientException
     */
    public function getKeyForJwtHeader(\stdClass $header): PublicKey
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
            if (isset($key->use) && $key->use !== 'sig') {
                continue;
            }

            if ($key->kty === $keyType) {
                if (!isset($header->kid) || $key->kid === $header->kid) {
                    return $this->convertJwkToPublicKey($key);
                }
            } else {
                if (isset($key->alg) && isset($key->kid) && $key->alg === $header->alg && $key->kid === $header->kid) {
                    return $this->convertJwkToPublicKey($key);
                }
            }
        }
        if (isset($header->kid)) {
            throw new OpenIDConnectClientException("Unable to find a key for $header->alg with kid `$header->kid`");
        }
        throw new OpenIDConnectClientException("Unable to find a key for $keyType");
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
     * @param \stdClass $key
     * @return PublicKey
     * @throws OpenIDConnectClientException
     */
    private function convertJwkToPublicKey(\stdClass $key): PublicKey
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
