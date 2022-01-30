<?php
declare(strict_types=1);

use JakubOnderka\Json;
use JakubOnderka\Jwks;
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
        $key = $jwks->getKeyForHeader($header);

        $serialized = serialize($jwks);
        $jwksNew = unserialize($serialized);
        $keyNew = $jwksNew->getKeyForHeader($header);

        $this->assertEquals($key, $keyNew);
    }
}
