<?php
declare(strict_types=1);

use JakubOnderka\Json;
use JakubOnderka\Jwt;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\TestCase;

class JwtTest extends TestCase
{
    public function testParse()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $jwt = new Jwt($token);

        $header = $jwt->header();
        $this->assertEquals('HS256', $header->alg);
        $this->assertEquals('JWT', $header->typ);

        $jwt->payload();
        $jwt->signature();
     }

    public function testCreateHmacSigned()
    {
         $jwt = Jwt::createHmacSigned([
             'ahoj' => 'světe', // unicode
         ], 'HS256', 'test');

         $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhaG9qIjoic3bEm3RlIn0.lIWI8qXF45Fjy6HwXqrnzDV8WKPXOdokQAufGuAZMeE', (string) $jwt);

         $jwtDecoded = new Jwt((string)$jwt);
         $this->assertEquals('HS256', $jwtDecoded->header()->alg);
         $this->assertEquals('JWT', $jwtDecoded->header()->typ);
         $this->assertEquals('světe', $jwtDecoded->payload()->ahoj);

         $this->assertTrue($jwtDecoded->verify(function (\stdClass $header) {
             return 'test';
         }));
    }

    /**
     * @dataProvider providesEc
     * @return void
     * @throws \JakubOnderka\JsonException
     */
    public function testCreateEcSigned(string $alg, string $curve, string $hash)
    {
        $privateKey = EC::loadPrivateKey($this->getPrivateKey($curve));

        $jwt = Jwt::createEcSigned([
            'ahoj' => 'světe', // unicode
        ], $privateKey);

        $jwtDecoded = new Jwt((string)$jwt);
        $this->assertEquals($alg, $jwtDecoded->header()->alg);
        $this->assertEquals('JWT', $jwtDecoded->header()->typ);
        $this->assertEquals('světe', $jwtDecoded->payload()->ahoj);
        $signature = $jwtDecoded->signature();

        $half = strlen($signature) / 2;
        $rawSignature = [
            'r' => new BigInteger(substr($signature, 0, $half), 256),
            's' => new BigInteger(substr($signature, $half), 256),
        ];

        $valid = $privateKey
            ->getPublicKey()
            ->withSignatureFormat('raw')
            ->withHash($hash)
            ->verify($jwtDecoded->withoutSignature(), $rawSignature);
        $this->assertTrue($valid);

        $this->assertTrue($jwtDecoded->verify(function (\stdClass $header) use ($privateKey) {
            return $privateKey->getPublicKey();
        }));
        $this->assertTrue($jwtDecoded->verify($privateKey->getPublicKey()));
    }

    /**
     * @dataProvider providesEdDsa
     * @return void
     * @throws \JakubOnderka\JsonException
     */
    public function testCreateEcSigned_edDsa(string $algo, string $curve)
    {
        $privateKey = EC::loadPrivateKey($this->getPrivateKey($curve));
        $publicKey = $privateKey->getPublicKey();

        $jwt = Jwt::createEcSigned([
            'ahoj' => 'světe', // unicode
        ], $privateKey);

        $jwtDecoded = new Jwt((string)$jwt);
        $this->assertEquals($algo, $jwtDecoded->header()->alg);
        $this->assertEquals('JWT', $jwtDecoded->header()->typ);
        $this->assertEquals('světe', $jwtDecoded->payload()->ahoj);
        $signature = $jwtDecoded->signature();

        $valid = $publicKey->verify($jwtDecoded->withoutSignature(), $signature);
        $this->assertTrue($valid);
        $this->assertTrue($jwtDecoded->verify($publicKey));
    }

    /**
     * @dataProvider provideRsa
     * @return void
     * @throws \JakubOnderka\JsonException
     */
    public function testCreateRsaSigned(string $alg, string $key, string $hash)
    {
        $privateKey = RSA::loadPrivateKey($this->getPrivateKey($key));

        $jwt = Jwt::createRsaSigned([
            'ahoj' => 'světe', // unicode
        ], $alg, $privateKey, 'kid');

        $jwtDecoded = new Jwt((string)$jwt);

        $this->assertEquals($alg, $jwtDecoded->header()->alg);
        $this->assertEquals('JWT', $jwtDecoded->header()->typ);
        $this->assertEquals('kid', $jwtDecoded->header()->kid);
        $this->assertEquals('světe', $jwtDecoded->payload()->ahoj);
        $signature = $jwtDecoded->signature();

        $publicKey = $privateKey
            ->getPublicKey()
            ->withHash($hash);

        if ($alg[0] === 'P') {
            $publicKey = $publicKey->withMGFHash($hash)
                ->withPadding(RSA::SIGNATURE_PSS);
        } else {
            $publicKey = $publicKey->withPadding(RSA::SIGNATURE_PKCS1);
        }

        $valid = $publicKey->verify($jwtDecoded->withoutSignature(), $signature);
        $this->assertTrue($valid);

        $this->assertTrue($jwtDecoded->verify(function (\stdClass $header) use ($privateKey) {
            return $privateKey->getPublicKey();
        }));
        $this->assertTrue($jwtDecoded->verify($privateKey->getPublicKey()));
    }

    /**
     * @throws \JakubOnderka\JsonException
     */
    private function getPrivateKey(string $keyType): string
    {
        static $keys;
        if ($keys === null) {
            $keys = Json::decode(file_get_contents(__DIR__ . '/data/private_keys.json'));
        }
        return $keys->{$keyType};
    }

    public function providesEc(): array
    {
        return [
            'ES256' => ['ES256', 'nistp256', 'sha256'],
            'ES384' => ['ES384', 'nistp384', 'sha384'],
            'ES512' => ['ES512', 'nistp521', 'sha512'],
        ];
    }

    public function providesEdDsa(): array
    {
        return [
            'EdDSA+Ed25519' => ['EdDSA', 'Ed25519'],
            'EdDSA+Ed448' => ['EdDSA', 'Ed448'],
        ];
    }

    public function provideRsa(): array
    {
        $output = [];
        foreach (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as $alg) {
            foreach (['RSA2048', 'RSA3072', 'RSA4096'] as $key) {
                $hash = 'sha' . substr($alg, 2, 3);
                $output["$alg+$key"] = [$alg, $key, $hash];
            }
        }
        return $output;
    }
}
