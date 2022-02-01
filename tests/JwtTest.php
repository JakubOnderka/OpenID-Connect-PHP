<?php
declare(strict_types=1);

use JakubOnderka\Jwt;
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

    public function testCreate()
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
}
