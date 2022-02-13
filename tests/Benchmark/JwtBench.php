<?php

namespace Benchmark;

use JakubOnderka\Json;
use JakubOnderka\OpenIDConnectClient\Jwt;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

class JwtBench
{
    const DEFAULT_ID_TOKEN = [
        "iss" => "https://example.com",
        "sub" => "24400320",
        "aud" => "s6BhdRkqt3",
        "nonce" => "n-0S6_WzA2Mj",
        "exp" => 20000,
        "iat" => 10000,
        "auth_time" => 1311280969,
        "acr" => "urn:mace:incommon:iap:silver",
        "at_hash" => "aUAkJG-u6x4RTWuILWy-CA",
    ];
    /**
     * @var mixed|\stdClass
     */
    private $privateKeys;

    /** @var EC\PublicKey */
    private $publicKey;

    /** @var Jwt */
    private $signed;

    public function __construct()
    {
        $this->privateKeys = Json::decode(file_get_contents(__DIR__ . '/../data/private_keys.json'));
        foreach ($this->privateKeys as $name => &$key) {
            if (substr($name, 0, 3) === 'RSA') {
                $key = RSA::loadPrivateKey($key);
            } else {
                $key = EC::loadPrivateKey($key);
            }
        }
    }

    /**
     * @ParamProviders({"provideHmacAlg"})
     * @Revs(10000)
     */
    public function benchHmacSign($params)
    {
        Jwt::createHmacSigned(self::DEFAULT_ID_TOKEN, $params['alg'], 'secret');
    }

    public function setUpBenchHmacVerify($params)
    {
        $this->signed[$params['alg']] = Jwt::createHmacSigned(self::DEFAULT_ID_TOKEN, $params['alg'], 'secret');
    }

    /**
     * @ParamProviders({"provideHmacAlg"})
     * @BeforeMethods("setUpBenchHmacVerify")
     * @Revs(10000)
     */
    public function benchHmacVerify($params)
    {
        assert($this->signed[$params['alg']]->verify('secret'));
    }

    /**
     * @ParamProviders({
     *     "provideRsaAlg",
     *     "provideRsaPrivateKey"
     * })
     * @Revs(100)
     */
    public function benchRsaSign($params)
    {
        Jwt::createRsaSigned(self::DEFAULT_ID_TOKEN, $params['alg'], $params['privateKey']);
    }

    public function setUpBenchRsaVerify($params)
    {
        $this->signed[$params['alg']] = Jwt::createRsaSigned(self::DEFAULT_ID_TOKEN, $params['alg'], $params['privateKey']);
    }

    /**
     * @ParamProviders({
     *     "provideRsaAlg",
     *     "provideRsaPrivateKey"
     * })
     * @BeforeMethods("setUpBenchRsaVerify")
     * @Revs(100)
     */
    public function benchRsaVerify($params)
    {
        assert($this->signed[$params['alg']]->verify($params['publicKey']));
    }

    /**
     * @ParamProviders({"provideEc"})
     * @Revs(1000)
     */
    public function benchEcSign($params)
    {
        Jwt::createEcSigned(self::DEFAULT_ID_TOKEN, $params['privateKey']);
    }

    public function setUpBenchEcVerify($params)
    {
        $this->signed = Jwt::createEcSigned(self::DEFAULT_ID_TOKEN, $params['privateKey']);
        $this->publicKey = $params['privateKey']->getPublicKey();
    }

    /**
     * @ParamProviders({"provideEc"})
     * @BeforeMethods("setUpBenchEcVerify")
     * @Revs(100)
     */
    public function benchEcVerify($params)
    {
        assert($this->signed->verify($this->publicKey));
    }

    public function provideHmacAlg(): \Generator
    {
        yield 'HS256' => ['alg' => 'HS256'];
        yield 'HS384' => ['alg' => 'HS384'];
        yield 'HS512' => ['alg' => 'HS512'];
    }

    public function provideRsaAlg(): \Generator
    {
        yield 'RS256' => ['alg' => 'RS256'];
        yield 'RS384' => ['alg' => 'RS384'];
        yield 'RS512' => ['alg' => 'RS512'];
    }

    public function provideRsaPrivateKey(): \Generator
    {
        yield 'RSA2048' => ['privateKey' => $this->privateKeys->RSA2048, 'publicKey' => $this->privateKeys->RSA2048->getPublicKey()];
        yield 'RSA3072' => ['privateKey' => $this->privateKeys->RSA3072, 'publicKey' => $this->privateKeys->RSA3072->getPublicKey()];
        yield 'RSA4096' => ['privateKey' => $this->privateKeys->RSA4096, 'publicKey' => $this->privateKeys->RSA4096->getPublicKey()];
    }

    public function provideEc(): \Generator
    {
        yield 'ES256' => ['privateKey' => $this->privateKeys->nistp256, 'alg' => 'ES256'];
        yield 'ES384' => ['privateKey' => $this->privateKeys->nistp384, 'alg' => 'ES384'];
        yield 'ES512' => ['privateKey' => $this->privateKeys->nistp521, 'alg' => 'ES512'];
    }
}
