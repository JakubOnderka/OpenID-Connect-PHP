<?php
declare(strict_types=1);

use JakubOnderka\Jwt;
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
         $jwtDecoded->signature();
    }

    public function testCreatePrivateKeySigned_ec()
    {
        $privateKey = \phpseclib3\Crypt\EC::createKey('nistp256');

        $jwt = Jwt::createPrivateKeySigned([
            'ahoj' => 'světe', // unicode
        ], 'ES256', $privateKey);

        $jwtDecoded = new Jwt((string)$jwt);
        $this->assertEquals('ES256', $jwtDecoded->header()->alg);
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
            ->withHash('sha256')
            ->verify($jwtDecoded->withoutSignature(), $rawSignature);
        $this->assertTrue($valid);
    }

    public function testCreatePrivateKeySigned_rsa()
    {
        $privateKey = \phpseclib3\Crypt\RSA::createKey();

        $jwt = Jwt::createPrivateKeySigned([
            'ahoj' => 'světe', // unicode
        ], 'RS256', $privateKey);

        $jwtDecoded = new Jwt((string)$jwt);
        $this->assertEquals('RS256', $jwtDecoded->header()->alg);
        $this->assertEquals('JWT', $jwtDecoded->header()->typ);
        $this->assertEquals('světe', $jwtDecoded->payload()->ahoj);
        $signature = $jwtDecoded->signature();

        $valid = $privateKey
            ->getPublicKey()
            ->withHash('sha256')
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->verify($jwtDecoded->withoutSignature(), $signature);
        $this->assertTrue($valid);
    }
}
