<?php

declare(strict_types=1);

namespace JakubOnderka\OpenIDConnectClient;

use JakubOnderka\Json;
use JakubOnderka\JsonException;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\RSA;
use function JakubOnderka\base64url_decode;
use function JakubOnderka\base64url_encode;

class Jwe
{
    /** @var string */
    private $token;

    public function __construct(string $token)
    {
        if (substr_count($token, '.') !== 4) {
            throw new \InvalidArgumentException("Token is not valid encrypted JWT (JWE), it must contains five parts separated by dots");
        }
        $this->token = $token;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->token;
    }

    /**
     * Decrypt JWE to JWT.
     * @param RSA\PrivateKey $key
     * @return Jwt
     * @throws JsonException
     */
    public function decrypt(RSA\PrivateKey $key): Jwt
    {
        $parts = explode('.', $this->token);

        $header = Json::decode(base64url_decode($parts[0]));
        $encryptedKey = base64url_decode($parts[1]);
        $initializationVector = base64url_decode($parts[2]);
        $cipherText = base64url_decode($parts[3]);
        $authenticationTag = base64url_decode($parts[4]);

        if (!isset($header->enc)) {
            throw new \RuntimeException("Required JWE header `enc` missing");
        }

        if (!isset($header->alg)) {
            throw new \RuntimeException("Required JWE header `alg` missing");
        }

        $key = $this->decryptKey($header->alg, $key, $encryptedKey);

        switch ($header->enc) {
            case 'A256GCM':
            case 'A192GCM':
            case 'A128GCM':
                $aes = new AES('GCM');
                $aes->setKeyLength(substr($header->enc, 1, 3));
                $aes->setNonce($initializationVector);
                $aes->setAAD($parts[0]);
                $aes->setTag($authenticationTag);
                $aes->setKey($key);
                $decrypted = $aes->decrypt($cipherText);
                break;
            case 'A256CBC-HS512':
            case 'A192CBC-HS384':
            case 'A128CBC-HS256':
                $keyLength = (int)substr($header->enc, 1, 3) / 8;
                if (strlen($key) !== $keyLength * 2) {
                    throw new \RuntimeException("Invalid key length");
                }

                $aesKey = substr($key, $keyLength);
                $hmacKey = substr($key, 0, $keyLength);

                $aes = new AES('CBC');
                $aes->setKeyLength($keyLength * 8);
                $aes->setIV($initializationVector);
                $aes->setKey($aesKey);
                $decrypted = $aes->decrypt($cipherText);

                $al = pack('J', strlen($parts[0]) * 8);
                $protectedData = "$parts[0]$initializationVector$cipherText$al";
                $hmac = hash_hmac('sha' . ($keyLength * 16), $protectedData, $hmacKey, true);
                if (!hash_equals(substr($hmac, 0, $keyLength), $authenticationTag)) {
                    throw new \RuntimeException("Could not validate");
                }
                break;
            default:
                throw new \RuntimeException("Unsupported enc $header->enc");
        }

        return new Jwt($decrypted);
    }

    /**
     * Decrypt symmetric encryption key with private RSA key
     *
     * @param string $alg
     * @param RSA\PrivateKey $rsa
     * @param string $encryptedKey
     * @return string Decrypted key
     */
    private function decryptKey(string $alg, RSA\PrivateKey $rsa, string $encryptedKey): string
    {
        switch ($alg) {
            case 'RSA-OAEP':
                return $rsa
                    ->withPadding(RSA::ENCRYPTION_OAEP)
                    ->withHash('sha1')
                    ->withMGFHash('sha1')
                    ->decrypt($encryptedKey);
            case 'RSA-OAEP-256':
                return $rsa
                    ->withPadding(RSA::ENCRYPTION_OAEP)
                    ->withHash('sha256')
                    ->withMGFHash('sha256')
                    ->decrypt($encryptedKey);
            case 'RSA1_5':
                return $rsa
                    ->withPadding(RSA::ENCRYPTION_PKCS1)
                    ->decrypt($encryptedKey);
            default:
                throw new \RuntimeException("Unsupported algo $alg");
        }
    }

    /**
     * Create encrypted JWE
     *
     * @param Jwt $jwt
     * @param RSA\PublicKey $publicKey
     * @param string $enc
     * @param string $alg
     * @return Jwe
     * @throws JsonException
     */
    public static function create(Jwt $jwt, RSA\PublicKey $publicKey, string $enc, string $alg): Jwe
    {
        $header = base64_encode(Json::encode(['typ' => 'JWT', 'alg' => $alg, 'enc' => $enc]));
        $keyLength = (int)substr($enc, 1, 3) / 8;
        $key = random_bytes($keyLength);

        switch ($enc) {
            case 'A256GCM':
            case 'A192GCM':
            case 'A128GCM':
                $initializationVector = random_bytes(12);
                $aes = new AES('GCM');
                $aes->setNonce($initializationVector);
                $aes->setKey($key);
                $aes->setAAD($header);
                $cipherText = $aes->encrypt((string)$jwt);
                $authenticationTag = $aes->getTag();
                break;
            case 'A256CBC-HS512':
            case 'A192CBC-HS384':
            case 'A128CBC-HS256':
                $initializationVector = random_bytes(16); // IV
                $aes = new AES('CBC');
                $aes->setIV($initializationVector);
                $aes->setKey($key);
                $cipherText = $aes->encrypt((string)$jwt);

                $al = pack('J', strlen($header) * 8);
                $protectedData = "$header$initializationVector$cipherText$al";
                $hmacKey = random_bytes($keyLength);
                $hmac = hash_hmac('sha' . ($keyLength * 16), $protectedData, $hmacKey, true);

                $authenticationTag = substr($hmac, 0, $keyLength);
                $key = "$hmacKey$key";
                break;
            default:
                throw new \RuntimeException("Unsupported enc $enc");
        }

        $encryptedKey = self::encryptKey($alg, $publicKey, $key);

        $token = $header . '.' .
            base64url_encode($encryptedKey) . '.' .
            base64url_encode($initializationVector) . '.' .
            base64url_encode($cipherText) . '.' .
            base64url_encode($authenticationTag);

        return new Jwe($token);
    }

    /**
     * Encrypt symmetric encryption key with public RSA key
     *
     * @param string $alg
     * @param RSA\PublicKey $rsa
     * @param string $key
     * @return string Encrypted key
     */
    private static function encryptKey(string $alg, RSA\PublicKey $rsa, string $key): string
    {
        switch ($alg) {
            case 'RSA-OAEP':
                return $rsa
                    ->withPadding(RSA::ENCRYPTION_OAEP)
                    ->withHash('sha1')
                    ->withMGFHash('sha1')
                    ->encrypt($key);
            case 'RSA-OAEP-256':
                return $rsa
                    ->withPadding(RSA::ENCRYPTION_OAEP)
                    ->withHash('sha256')
                    ->withMGFHash('sha256')
                    ->encrypt($key);
            case 'RSA1_5':
                return $rsa
                    ->withPadding(RSA::ENCRYPTION_PKCS1)
                    ->encrypt($key);
            default:
                throw new \RuntimeException("Unsupported algo $alg");
        }
    }
}
