<?php
declare(strict_types=1);

use JakubOnderka\Json;
use JakubOnderka\OpenIDConnectClient\Jwks;
use PHPUnit\Framework\TestCase;

class JwksTest extends TestCase
{
    public function testSleepAndWakeup()
    {
        $header = new \stdClass();
        $header->kid = 'konnectd-tokens-signing-key';
        $header->alg = 'RS256';

        $content = Json::decode(file_get_contents(__DIR__ . "/data/jwks-ps256.json"));
        $jwks = new Jwks($content->keys);
        $key = $jwks->getKeyForJwtHeader($header);

        $serialized = serialize($jwks);
        $jwksNew = unserialize($serialized);
        $keyNew = $jwksNew->getKeyForJwtHeader($header);

        $this->assertEquals($key, $keyNew);
    }

    public function testAdd()
    {
        $keys = Json::decode(file_get_contents(__DIR__ . '/data/private_keys.json'));

        // ESXXX
        foreach (['nistp256', 'nistp384', 'nistp521'] as $type) {
            $privateKey = \phpseclib3\Crypt\EC::loadPrivateKey($keys->$type);
            $publicKey = $privateKey->getPublicKey();

            $jwks = new Jwks();
            $jwks->addPublicKey($publicKey);
            $fetched = $jwks->getKeyForJwtHeader((object)['alg' => 'ES256']);

            $this->assertEquals($publicKey->toString('xml'), $fetched->toString('xml'));
        }

        // RSA
        foreach ([2048, 3072, 4096] as $size) {
            $privateKey = \phpseclib3\Crypt\RSA\PrivateKey::loadPrivateKey($keys->{"RSA$size"});
            $publicKey = $privateKey->getPublicKey();

            $jwks = new Jwks();
            $jwks->addPublicKey($publicKey);
            $fetched = $jwks->getKeyForJwtHeader((object)['alg' => 'RS256']);

            $this->assertEquals($publicKey->toString('xml'), $fetched->toString('xml'));
        }

        // Ed
        $privateKey = \phpseclib3\Crypt\EC::loadPrivateKey($keys->Ed25519);
        $publicKey = $privateKey->getPublicKey();

        $jwks = new Jwks();
        $jwks->addPublicKey($publicKey);
        $fetched = $jwks->getKeyForJwtHeader((object)['alg' => 'EdDSA']);

        $this->assertEquals($publicKey->toString('PKCS8'), $fetched->toString('PKCS8'));
    }
}
