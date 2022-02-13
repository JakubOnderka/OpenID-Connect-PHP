<?php
declare(strict_types=1);

namespace JakubOnderka {
    function setTime(int $time)
    {
        global $TIME;
        $TIME = $time;
    }

    // Mock time
    function time()
    {
        global $TIME;
        return $TIME;
    }
}

namespace {

    use JakubOnderka\OpenIDConnectClient\Jwt;
    use JakubOnderka\OpenIDConnectClient;
    use JakubOnderka\OpenIDConnectClientException;
    use JakubOnderka\TokenValidationFailed;
    use PHPUnit\Framework\MockObject\MockObject;
    use PHPUnit\Framework\TestCase;

    class ValidateTokenTest extends TestCase
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

        public function testValidateIdToken()
        {
            $client = $this->prepare();

            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_ID_TOKEN));

            JakubOnderka\setTime(10001);
            $this->assertTrue($client->authenticate());
        }

        public function testValidateIdToken_invalidIssuer()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $token['iss'] = 'https://example.org';
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);
            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'It didn\'t pass issuer validator (expected: `https://example.com`, actual: `https://example.org`)');
        }

        public function testValidateIdToken_withAzp()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $token['azp'] = $token['aud'];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);
            $this->assertTrue($client->authenticate());
        }

        public function testValidateIdToken_withAudArray()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $token['aud'] = [$token['aud']];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);
            $this->assertTrue($client->authenticate());
        }

        public function testValidateIdToken_withMultipleAud()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $token['aud'] = [$token['aud'], 'abcd'];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Multiple audiences provided, but `azp` claim not provided');
        }

        public function testValidateIdToken_withMultipleAud_withAzp()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $token['azp'] = $token['aud'];
            $token['aud'] = [$token['aud'], 'abcd'];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);
            $this->assertTrue($client->authenticate());
        }

        public function testValidateIdToken_expired()
        {
            $client = $this->prepare();
            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_ID_TOKEN));
            JakubOnderka\setTime(20001);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Token is already expired, expired at 1970-01-01T05:33:20+00:00');
        }

        public function testValidateIdToken_expirationAsDouble()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $token['exp'] = $token['exp'] + 0.1;
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);
            $this->assertTrue($client->authenticate());
        }

        public function testValidateIdToken_invalidIat()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $token['iat'] = "invalid";
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);
            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Required `iat` claim provided, but type is incorrect (expected: `int`, actual: `string`)');
        }

        public function testValidateIdToken_iatNotProvided()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            unset($token['iat']);
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(10001);
            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Required `iat` claim not provided');
        }

        public function testValidateIdToken_iatSlack()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            $client->method('requestTokens')->willReturn($this->createToken($token));

            // Little bit before
            JakubOnderka\setTime(9999);
            $client->authenticate();

            // Too much before
            JakubOnderka\setTime(5000);
            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Token was issued at 1970-01-01T02:46:40+00:00, that is more than 600 seconds in future');

            // Little bit after
            JakubOnderka\setTime(10001);
            $client->authenticate();

            // Too much after
            JakubOnderka\setTime(11000);
            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Token was issued at 1970-01-01T02:46:40+00:00, that is more than 600 seconds ago');
        }

        public function testValidateIdToken_nonceNotProvided()
        {
            $client = $this->prepare([
                OpenIDConnectClient::STATE => 'state',
                OpenIDConnectClient::NONCE => 'invalid_nonce',
            ]);

            $token = self::DEFAULT_ID_TOKEN;
            unset($token['nonce']);
            $client->method('requestTokens')->willReturn($this->createToken($token));
            JakubOnderka\setTime(10001);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Required `nonce` claim not provided');
        }

        public function testValidateIdToken_incorrectNonce()
        {
            $client = $this->prepare([
                OpenIDConnectClient::STATE => 'state',
                OpenIDConnectClient::NONCE => 'invalid_nonce',
            ]);

            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_ID_TOKEN));
            JakubOnderka\setTime(10001);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Nonce do not match (expected: `invalid_nonce`, actual: `n-0S6_WzA2Mj`)');
        }

        public function testValidateIdToken_invalidAccessToken()
        {
            $client = $this->prepare();

            $requestTokens = $this->createToken(self::DEFAULT_ID_TOKEN);
            $requestTokens->access_token = 'IxC0B76vlWl3fiQhAwZUmD0hr_PPwC9hSIXRdoUslPU=';

            $client->method('requestTokens')->willReturn($requestTokens);
            JakubOnderka\setTime(10001);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, '`at_hash` claim do not match to provided access token (expected: `-jPtKOXggsT1tkIhQ9UWWw`, actual: `aUAkJG-u6x4RTWuILWy-CA`)');
        }

        public function testValidateIdToken_invalidAccessToken_withoutAtHash()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_ID_TOKEN;
            unset($token['at_hash']);
            $requestTokens = $this->createToken($token);
            $requestTokens->access_token = 'IxC0B76vlWl3fiQhAwZUmD0hr_PPwC9hSIXRdoUslPU=';

            $client->method('requestTokens')->willReturn($requestTokens);
            JakubOnderka\setTime(10001);

            $this->assertTrue($client->authenticate());
        }

        public function testValidateIdToken_invalidClientId()
        {
            $client = $this->prepare();
            $client->setClientID('invalid');
            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_ID_TOKEN));

            JakubOnderka\setTime(10001);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Client ID do not match to `aud` claim (expected: `invalid`, actual: `s6BhdRkqt3`)');
        }

        public function testVerifyAndValidateLogoutToken()
        {
            $jwt = new Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJpYXQiOjE0NzE1NjYxNTQsImp0aSI6ImJXSnEiLCJzaWQiOiIwOGE1MDE5Yy0xN2UxLTQ5NzctOGY0Mi02NWExMjg0M2VhMDIiLCJldmVudHMiOnsiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9ldmVudC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9fX0.McD4YIsDHb8Ug5B4MRfpisQaxCCXi6EUPerx3AH3v0Q");
            $client = new OpenIDConnectClient('https://server.example.com', 's6BhdRkqt3', 'ahoj');
            JakubOnderka\setTime(1471566155);
            $client->verifyAndValidateLogoutToken($jwt);
            $this->assertTrue(true);
        }

        /**
         * @throws \JakubOnderka\JsonException
         */
        private function createToken(array $idTokenData): \stdClass
        {
            $idToken = Jwt::createHmacSigned($idTokenData, 'HS256', '');

            $requestTokens = new \stdClass();
            $requestTokens->id_token = (string)$idToken;
            $requestTokens->access_token = 'ya29.eQETFbFOkAs8nWHcmYXKwEi0Zz46NfsrUU_KuQLOLTwWS40y6Fb99aVzEXC0U14m61lcPMIr1hEIBA';
            return $requestTokens;
        }

        private function checkException(\Closure $closure, string $message)
        {
            try {
                $closure();
                $this->fail('No exception thrown');
            } catch (OpenIDConnectClientException $e) {
                $this->assertInstanceOf(TokenValidationFailed::class, $e->getPrevious(), $e->getMessage());
                $this->assertEquals($message, $e->getPrevious()->getMessage());
            }
        }

        /**
         * @return OpenIDConnectClient|MockObject
         */
        private function prepare(array $sessions = null)
        {
            if (!$sessions) {
                $sessions = [
                    OpenIDConnectClient::STATE => 'state',
                    OpenIDConnectClient::NONCE => 'n-0S6_WzA2Mj',
                ];
            }

            $_REQUEST = [];
            $_REQUEST['code'] = '123';
            $_REQUEST['state'] = 'state';

            $client = $this->getMockBuilder(OpenIDConnectClient::class)
                ->setMethods(['requestTokens', 'getProviderConfigValue', 'getWellKnownIssuer', 'verifyJwtSignature', 'fetchURL', 'getSessionKey', 'unsetSessionKey'])
                ->setConstructorArgs(['https://jwt.io/'])
                ->getMock();
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJwtSignature')->willReturn(true);
            $client->method('fetchURL')->with($this->never());
            $client->method('unsetSessionKey')->willReturn(true);
            $client->method('getWellKnownIssuer')->willReturn('https://example.com');
            $client->method('getSessionKey')->will($this->returnCallback(function (string $key) use ($sessions): string {
                return $sessions[$key];
            }));

            $client->setIssuer('https://example.com');
            $client->setClientID('s6BhdRkqt3');
            return $client;
        }
    }
}
