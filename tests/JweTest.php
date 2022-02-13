<?php
declare(strict_types=1);

use JakubOnderka\Json;
use JakubOnderka\Jwt;
use JakubOnderka\OpenIDConnectClient\Jwe;
use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\TestCase;

class JweTest extends TestCase
{
    /** @var RSA\PrivateKey */
    private $privateKey;

    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->privateKey = RSA::loadPrivateKey(Json::decode(file_get_contents(__DIR__ . '/data/private_keys.json'))->RSA2048);
    }

    /**
     * @dataProvider provide
     * @return void
     * @throws \JakubOnderka\JsonException
     */
    public function testSleepAndWakeup(string $alg, string $enc)
    {
        $jwt = Jwt::createHmacSigned(['test' => 'test'], 'HS256', 'ahoj');

        $jwe = Jwe::create($jwt, $this->privateKey->getPublicKey(), $enc, $alg);
        $jwtDecrypted = $jwe->decrypt($this->privateKey);

        $this->assertEquals('test', $jwtDecrypted->payload()->test);
    }

    public function provide(): array
    {
        $output = [];
        foreach (['RSA-OAEP-256', 'RSA-OAEP', 'RSA1_5'] as $alg) {
            foreach (['A256GCM', 'A192GCM', 'A128GCM', 'A256CBC-HS512', 'A192CBC-HS384', 'A128CBC-HS256'] as $enc) {
                $output["$alg+$enc"] = [$alg, $enc];
            }
        }
        return $output;
    }
}
