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

    use JakubOnderka\Json;
    use JakubOnderka\Jwt;
    use JakubOnderka\OpenIDConnectClient;
    use JakubOnderka\OpenIDConnectClientException;
    use JakubOnderka\TokenValidationFailed;
    use PHPUnit\Framework\MockObject\MockObject;
    use PHPUnit\Framework\TestCase;
    use function JakubOnderka\base64url_encode;

    class VerifyJwtClaimsTest extends TestCase
    {
        const DEFAULT_TOKEN = [
            "iss" => "https://example.com",
            "sub" => "24400320",
            "aud" => "s6BhdRkqt3",
            "nonce" => "n-0S6_WzA2Mj",
            "exp" => 1311281970,
            "iat" => 1311280970,
            "auth_time" => 1311280969,
            "acr" => "urn:mace:incommon:iap:silver",
            "at_hash" => "aUAkJG-u6x4RTWuILWy-CA",
        ];

        public function testVerifyJwtClaims()
        {
            $client = $this->prepare();

            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_TOKEN));

            JakubOnderka\setTime(1311280971);
            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJwtClaims_withAzp()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_TOKEN;
            $token['azp'] = $token['aud'];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(1311280971);
            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJwtClaims_withAudArray()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_TOKEN;
            $token['aud'] = [$token['aud']];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(1311280971);
            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJwtClaims_withMultipleAud()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_TOKEN;
            $token['aud'] = [$token['aud'], 'abcd'];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(1311280971);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Multiple audiences provided, but `azp` claim not provided');
        }

        public function testVerifyJwtClaims_withMultipleAud_withAzp()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_TOKEN;
            $token['azp'] = $token['aud'];
            $token['aud'] = [$token['aud'], 'abcd'];
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(1311280971);
            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJwtClaims_expirationAsDouble()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_TOKEN;
            $token['exp'] = $token['exp'] + 0.1;
            $client->method('requestTokens')->willReturn($this->createToken($token));

            JakubOnderka\setTime(1311280971);
            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJwtClaims_nonceNotProvided()
        {
            $client = $this->prepare([
                OpenIDConnectClient::STATE => 'state',
                OpenIDConnectClient::NONCE => 'invalid_nonce',
            ]);

            $token = self::DEFAULT_TOKEN;
            unset($token['nonce']);
            $client->method('requestTokens')->willReturn($this->createToken($token));
            JakubOnderka\setTime(1311280971);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Required `nonce` claim not provided');
        }

        public function testVerifyJwtClaims_incorrectNonce()
        {
            $client = $this->prepare([
                OpenIDConnectClient::STATE => 'state',
                OpenIDConnectClient::NONCE => 'invalid_nonce',
            ]);

            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_TOKEN));
            JakubOnderka\setTime(1311280971);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Nonce do not match (expected: `invalid_nonce`, actual: `n-0S6_WzA2Mj`)');
        }

        public function testVerifyJwtClaims_invalidAccessToken()
        {
            $client = $this->prepare();

            $requestTokens = $this->createToken(self::DEFAULT_TOKEN);
            $requestTokens->access_token = 'IxC0B76vlWl3fiQhAwZUmD0hr_PPwC9hSIXRdoUslPU=';

            $client->method('requestTokens')->willReturn($requestTokens);
            JakubOnderka\setTime(1311280971);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, '`at_hash` claim do not match (expected: `-jPtKOXggsT1tkIhQ9UWWw`, actual: `aUAkJG-u6x4RTWuILWy-CA`)');
        }

        public function testVerifyJwtClaims_invalidAccessToken_withoutAtHash()
        {
            $client = $this->prepare();

            $token = self::DEFAULT_TOKEN;
            unset($token['at_hash']);
            $requestTokens = $this->createToken($token);
            $requestTokens->access_token = 'IxC0B76vlWl3fiQhAwZUmD0hr_PPwC9hSIXRdoUslPU=';

            $client->method('requestTokens')->willReturn($requestTokens);
            JakubOnderka\setTime(1311280971);

            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJwtClaims_expired()
        {
            $client = $this->prepare();
            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_TOKEN));
            JakubOnderka\setTime(1311281971);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Token is already expired (expected: `1311281971`, actual: `1311281970`)');
        }

        public function testVerifyJwtClaims_invalidClientId()
        {
            $client = $this->prepare();
            $client->setClientID('invalid');
            $client->method('requestTokens')->willReturn($this->createToken(self::DEFAULT_TOKEN));

            JakubOnderka\setTime(1311280971);

            $this->checkException(function () use ($client) {
                $client->authenticate();
            }, 'Client ID do not match to `aud` claim (expected: `invalid`, actual: `s6BhdRkqt3`)');
        }

        public function testVerifyLogoutToken()
        {
            $jwt = new Jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMSIsImF1ZCI6InM2QmhkUmtxdDMiLCJpYXQiOjE0NzE1NjYxNTQsImp0aSI6ImJXSnEiLCJzaWQiOiIwOGE1MDE5Yy0xN2UxLTQ5NzctOGY0Mi02NWExMjg0M2VhMDIiLCJldmVudHMiOnsiaHR0cDovL3NjaGVtYXMub3BlbmlkLm5ldC9ldmVudC9iYWNrY2hhbm5lbC1sb2dvdXQiOnt9fX0.McD4YIsDHb8Ug5B4MRfpisQaxCCXi6EUPerx3AH3v0Q");
            $client = new OpenIDConnectClient();
            $client->setClientID('s6BhdRkqt3');
            $client->setClientSecret('ahoj');
            $client->setIssuer('https://server.example.com');
            JakubOnderka\setTime(1471566155);
            $client->verifyAndValidateLogoutToken($jwt);
            $this->assertTrue(true);
        }

        /**
         * @throws \JakubOnderka\JsonException
         */
        private function createToken(array $idTokenData): \stdClass
        {
            $idToken = base64url_encode(Json::encode(['alg' => 'HS256', 'type' => 'JWT']));
            $idToken .= '.' . base64url_encode(Json::encode($idTokenData));
            $idToken .= '.' . base64url_encode(sha1('', true)); // fake signature, it is not verified in this test

            $requestTokens = new \stdClass();
            $requestTokens->id_token = $idToken;
            $requestTokens->access_token = 'ya29.eQETFbFOkAs8nWHcmYXKwEi0Zz46NfsrUU_KuQLOLTwWS40y6Fb99aVzEXC0U14m61lcPMIr1hEIBA';
            return $requestTokens;
        }

        private function checkException(\Closure $closure, string $message)
        {
            try {
                $closure();
                $this->fail('No exception thrown');
            } catch (Exception $e) {
                $this->assertInstanceOf(OpenIDConnectClientException::class, $e);
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
                ->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature', 'fetchURL', 'getSessionKey', 'unsetSessionKey'])
                ->getMock();
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);
            $client->method('fetchURL')->with($this->never());
            $client->method('unsetSessionKey')->willReturn(true);
            $client->method('getSessionKey')->will($this->returnCallback(function (string $key) use ($sessions): string {
                return $sessions[$key];
            }));

            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('https://example.com');
            $client->setClientID('s6BhdRkqt3');
            return $client;
        }
    }
}
