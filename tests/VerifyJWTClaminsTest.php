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
    use JakubOnderka\OpenIDConnectClient;
    use PHPUnit\Framework\MockObject\MockObject;
    use PHPUnit\Framework\TestCase;

    class VerifyJWTClaminsTest extends TestCase
    {
        public function testVerifyJWTclaims()
        {
            $this->prepare();

            $requestTokens = new \stdClass();
            $requestTokens->id_token = 'eyJraWQiOiJtcVQ1QTNMT1NJSGJwS3JzY2IzRUhHcnItV0lGUmZMZGFxWl81SjlHUjlzIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiItdi1sY2FlNXJHRy1qbHZ6dXY5WTlIN1I4Tm1BZU0yLWtoMHFXYi12UElFPSIsImF1ZCI6InRlc3RfcnBfeXQyIiwiYWNyIjoiTGV2ZWw0IiwiYXV0aF90aW1lIjoxNDk3NjA1MjE4LCJhbXIiOiJCYW5rSUQiLCJpc3MiOiJodHRwczpcL1wvb2lkYy15dDIuZGlmaS5lb24ubm9cL2lkcG9ydGVuLW9pZGMtcHJvdmlkZXJcLyIsInBpZCI6IjIzMDc5NDEwOTE4IiwiZXhwIjoxNDk3NjA1MzgyLCJsb2NhbGUiOiJuYiIsImlhdCI6MTQ5NzYwNTI2Miwibm9uY2UiOiJtaW5fZmluZV9ub25jZV92ZXJkaSIsImp0aSI6IkhnYjN6d085ZzBiam1TYkNDdFFDeE1vd3NaRXUwMGxDSjJFeGc0Wmh2M2c9In0.Pl9APC3_GGJBLYR3AqZRC8-fjOWdIW3eQAn2zbqstGEyv8AJ6yPLiH0EA4e1RgHxK-dPwtydJF0fV-1aiPjDGYM8d-saN26WBlRyvBRH1j8A9smQv5XxJoXssfxMr-t1ZB5wDM37MOkwMF4zTNPVmyeQ0qM0PAudG7ZpT0gWPksQIWOoSk4A--MoOHPBy41xXWSpOvUh3jBqrnWEcZpqS785Ufofc6cDfXk_wM_-EMAlS-UExMq-hH60nPwXmR0cBNW3GV2xm_frYyqBYnxXoELmzREijpeSyiELTqn2k4nwCjeiGDXXs_Nw12D2KpWLDctqqsUtTTRUhsnCPSoDng';
            $requestTokens->access_token = 'IxC0B76vlWl3fiQhAwZUmD0hr_PPwC9hSIXRdoUslPU=';

            /** @var OpenIDConnectClient | MockObject $client */
            $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature', 'getSessionKey'])->getMock();
            $client->method('requestTokens')->willReturn($requestTokens);
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);

            $client->method('getSessionKey')->will($this->returnCallback(function (string $key): string {
                if ($key === OpenIDConnectClient::STATE) {
                    return 'state';
                } else if ($key === OpenIDConnectClient::NONCE) {
                    return 'min_fine_nonce_verdi';
                }
                throw new InvalidArgumentException($key);
            }));

            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('https://oidc-yt2.difi.eon.no/idporten-oidc-provider/');
            $client->setClientID('test_rp_yt2');
            JakubOnderka\setTime(1497605382);
            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJWTclaims_incorrect_nonce()
        {
            $this->prepare();

            $requestTokens = new \stdClass();
            $requestTokens->id_token = 'eyJraWQiOiJtcVQ1QTNMT1NJSGJwS3JzY2IzRUhHcnItV0lGUmZMZGFxWl81SjlHUjlzIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiItdi1sY2FlNXJHRy1qbHZ6dXY5WTlIN1I4Tm1BZU0yLWtoMHFXYi12UElFPSIsImF1ZCI6InRlc3RfcnBfeXQyIiwiYWNyIjoiTGV2ZWw0IiwiYXV0aF90aW1lIjoxNDk3NjA1MjE4LCJhbXIiOiJCYW5rSUQiLCJpc3MiOiJodHRwczpcL1wvb2lkYy15dDIuZGlmaS5lb24ubm9cL2lkcG9ydGVuLW9pZGMtcHJvdmlkZXJcLyIsInBpZCI6IjIzMDc5NDEwOTE4IiwiZXhwIjoxNDk3NjA1MzgyLCJsb2NhbGUiOiJuYiIsImlhdCI6MTQ5NzYwNTI2Miwibm9uY2UiOiJtaW5fZmluZV9ub25jZV92ZXJkaSIsImp0aSI6IkhnYjN6d085ZzBiam1TYkNDdFFDeE1vd3NaRXUwMGxDSjJFeGc0Wmh2M2c9In0.Pl9APC3_GGJBLYR3AqZRC8-fjOWdIW3eQAn2zbqstGEyv8AJ6yPLiH0EA4e1RgHxK-dPwtydJF0fV-1aiPjDGYM8d-saN26WBlRyvBRH1j8A9smQv5XxJoXssfxMr-t1ZB5wDM37MOkwMF4zTNPVmyeQ0qM0PAudG7ZpT0gWPksQIWOoSk4A--MoOHPBy41xXWSpOvUh3jBqrnWEcZpqS785Ufofc6cDfXk_wM_-EMAlS-UExMq-hH60nPwXmR0cBNW3GV2xm_frYyqBYnxXoELmzREijpeSyiELTqn2k4nwCjeiGDXXs_Nw12D2KpWLDctqqsUtTTRUhsnCPSoDng';
            $requestTokens->access_token = 'IxC0B76vlWl3fiQhAwZUmD0hr_PPwC9hSIXRdoUslPU=';

            /** @var OpenIDConnectClient | MockObject $client */
            $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature', 'getSessionKey'])->getMock();
            $client->method('requestTokens')->willReturn($requestTokens);
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);

            $client->method('getSessionKey')->will($this->returnCallback(function (string $key): string {
               if ($key === OpenIDConnectClient::STATE) {
                   return 'state';
               } else if ($key === OpenIDConnectClient::NONCE) {
                   return 'min_fine_nonce_verdi2';
               }
               throw new InvalidArgumentException($key);
            }));

            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('https://oidc-yt2.difi.eon.no/idporten-oidc-provider/');
            $client->setClientID('test_rp_yt2');
            JakubOnderka\setTime(1497605382);

            $this->expectExceptionMessage('Could not validate claims, nonce do not match');
            $client->authenticate();
        }

        public function testVerifyJWTclaims_with_at_hash()
        {
            $this->prepare();

            /** @var OpenIDConnectClient | MockObject $client */
            $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature'])->getMock();
            $client->method('requestTokens')->willReturn($this->getGoogleToken());
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);
            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('accounts.google.com');
            $client->setClientID('407408718192.apps.googleusercontent.com');
            JakubOnderka\setTime(1432086478);
            $this->assertTrue($client->authenticate());
        }

        public function testVerifyJWTclaims_invalid_access_token()
        {
            $this->prepare();

            $requestTokens = $this->getGoogleToken();
            $requestTokens->access_token = 'IxC0B76vlWl3fiQhAwZUmD0hr_PPwC9hSIXRdoUslPU=';

            /** @var OpenIDConnectClient | MockObject $client */
            $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature'])->getMock();
            $client->method('requestTokens')->willReturn($requestTokens);
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);
            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('accounts.google.com');
            $client->setClientID('407408718192.apps.googleusercontent.com');
            JakubOnderka\setTime(1432086478);

            $this->expectExceptionMessage('Could not validate claims, at_hash do not match');
            $client->authenticate();
        }

        public function testVerifyJWTclaims_expired()
        {
            $this->prepare();

            /** @var OpenIDConnectClient | MockObject $client */
            $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature'])->getMock();
            $client->method('requestTokens')->willReturn($this->getGoogleToken());
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);
            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('accounts.google.com');
            $client->setClientID('407408718192.apps.googleusercontent.com');
            JakubOnderka\setTime(time());

            $this->expectExceptionMessage('Could not validate claims, token is already expired');
            $client->authenticate();
        }

        public function testVerifyJWTclaims_expired_no_leeway()
        {
            $this->prepare();

            /** @var OpenIDConnectClient | MockObject $client */
            $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature'])->getMock();
            $client->method('requestTokens')->willReturn($this->getGoogleToken());
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);
            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('accounts.google.com');
            $client->setClientID('407408718192.apps.googleusercontent.com');
            $client->setLeeway(0);
            JakubOnderka\setTime(1432086479);

            $this->expectExceptionMessage('Could not validate claims, token is already expired');
            $client->authenticate();
        }

        public function testVerifyJWTclaims_invalid_client_id()
        {
            $this->prepare();

            /** @var OpenIDConnectClient | MockObject $client */
            $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['requestTokens', 'getProviderConfigValue', 'verifyJWTsignature'])->getMock();
            $client->method('requestTokens')->willReturn($this->getGoogleToken());
            $client->method('getProviderConfigValue')->willReturn(true);
            $client->method('verifyJWTsignature')->willReturn(true);
            $client->setProviderURL('https://jwt.io/');
            $client->setIssuer('accounts.google.com');
            $client->setClientID('407408718192.apps.googleusercontent.com___INVALID');
            JakubOnderka\setTime(time());

            $this->expectExceptionMessage('Could not validate claims, client ID do not match');
            $client->authenticate();
        }

        private function getGoogleToken(): \stdClass
        {
            $requestTokens = new \stdClass();
            $requestTokens->id_token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjJhODc0MjBlY2YxNGU5MzRmOWY5MDRhMDE0NzY4MTMyMDNiMzk5NGIifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTEwMTY5NDg0NDc0Mzg2Mjc2MzM0IiwiYXpwIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXRfaGFzaCI6ImFVQWtKRy11Nng0UlRXdUlMV3ktQ0EiLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJpYXQiOjE0MzIwODI4NzgsImV4cCI6MTQzMjA4NjQ3OH0.xSwhf4KvEztFFhVj4YdgKFOC8aPEoLAAZcXDWIh6YBXpfjzfnwYhaQgsmCofzOl53yirpbj5h7Om5570yzlUziP5TYNIqrA3Nyaj60-ZyXY2JMIBWYYMr3SRyhXdW0Dp71tZ5IaxMFlS8fc0MhSx55ZNrCV-3qmkTLeTTY1_4Jc';
            $requestTokens->access_token = 'ya29.eQETFbFOkAs8nWHcmYXKwEi0Zz46NfsrUU_KuQLOLTwWS40y6Fb99aVzEXC0U14m61lcPMIr1hEIBA';
            return $requestTokens;
        }

        private function prepare()
        {
            $_REQUEST = [];
            $_SESSION = [];

            $_REQUEST['code'] = '123';
            $_REQUEST['state'] = 'state';
            $_SESSION['openid_connect_state'] = 'state';
        }
    }
}
