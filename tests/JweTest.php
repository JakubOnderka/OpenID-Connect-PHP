<?php
declare(strict_types=1);

use JakubOnderka\Json;
use JakubOnderka\OpenIDConnectClient\Jwt;
use JakubOnderka\OpenIDConnectClient\Jwe;
use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\TestCase;

class JweTest extends TestCase
{
    /**
     * @dataProvider provide
     * @return void
     * @throws \JakubOnderka\JsonException
     */
    public function testSleepAndWakeup(string $alg, string $enc, RSA\PrivateKey $privateKey)
    {
        $jwt = Jwt::createHmacSigned(['test' => 'test'], 'HS256', 'ahoj');

        $jwe = Jwe::create($jwt, $privateKey->getPublicKey(), $enc, $alg);
        $jwtDecrypted = $jwe->decrypt($privateKey);

        $this->assertEquals('test', $jwtDecrypted->payload()->test);
    }

    public function provide(): array
    {
        $keys = Json::decode(file_get_contents(__DIR__ . '/data/private_keys.json'));

        $output = [];
        foreach (['RSA2048', 'RSA3072', 'RSA4096'] as $key) {
            $privateKey = RSA\PrivateKey::loadPrivateKey($keys->{$key});
            foreach (['RSA-OAEP-256', 'RSA-OAEP', 'RSA1_5'] as $alg) {
                foreach (['A256GCM', 'A192GCM', 'A128GCM', 'A256CBC-HS512', 'A192CBC-HS384', 'A128CBC-HS256'] as $enc) {
                    $output["$alg+$enc+$key"] = [$alg, $enc, $privateKey];
                }
            }
        }
        return $output;
    }
}
