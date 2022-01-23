<?php
declare(strict_types=1);

use Jumbojett\OpenIDConnectClient;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class TokenVerificationTest extends TestCase
{
    /**
     * @param string $alg
     * @param string $jwt
     * @throws \Jumbojett\OpenIDConnectClientException
     * @dataProvider providesTokens
     */
    public function testTokenVerification(string $alg, string $jwt)
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchUrl'])->getMock();
        $client->method('fetchUrl')->willReturn(file_get_contents(__DIR__ . "/data/jwks-$alg.json"));
        $client->setProviderURL('https://jwt.io/');
        $client->providerConfigParam(['jwks_uri' => 'https://jwt.io/.well-known/jwks.json']);
        $verified = $client->verifyJWTsignature($jwt);
        $this->assertTrue($verified);
    }

    /**
     * @param string $alg
     * @param string $jwt
     * @throws \Jumbojett\OpenIDConnectClientException
     * @dataProvider providesTokens
     */
    public function testTokenVerification_invalidKid(string $alg, string $jwt)
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchUrl'])->getMock();

        $certs = json_decode(file_get_contents(__DIR__ . "/data/jwks-$alg.json"));
        $certs->keys[0]->kid = 'different_kid';

        $client->method('fetchUrl')->willReturn(json_encode($certs));
        $client->setProviderURL('https://jwt.io/');
        $client->providerConfigParam(['jwks_uri' => 'https://jwt.io/.well-known/jwks.json']);

        $this->expectExceptionMessage('Unable to find a key for PS256 with kid `konnectd-tokens-signing-key`');
        $client->verifyJWTsignature($jwt);
    }

    /**
     * @param string $jwt
     * @return void
     * @throws \Jumbojett\OpenIDConnectClientException
     * @dataProvider providesHsTokens
     */
    public function testHsTokenVerification(string $jwt)
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchUrl'])->getMock();
        $client->expects($this->never())->method('fetchUrl');
        $client->setProviderURL('https://jwt.io/');
        $client->setClientSecret('secret');
        $client->providerConfigParam(['jwks_uri' => 'https://jwt.io/.well-known/jwks.json']);
        $verified = $client->verifyJWTsignature($jwt);
        $this->assertTrue($verified);

        $client->setClientSecret('secret__invalid');
        $verified = $client->verifyJWTsignature($jwt);
        $this->assertFalse($verified);
    }

    public function providesTokens()
    {
        return [
            'PS256' => ['ps256', 'eyJhbGciOiJQUzI1NiIsImtpZCI6Imtvbm5lY3RkLXRva2Vucy1zaWduaW5nLWtleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJrcG9wLWh0dHBzOi8va29wYW5vLmRlbW8vbWVldC8iLCJleHAiOjE1NjgzNzE0NjEsImp0aSI6IkpkR0tDbEdOTXl2VXJpcmlRRUlWUXZCVmttT2FfQkRjIiwiaWF0IjoxNTY4MzcxMjIxLCJpc3MiOiJodHRwczovL2tvcGFuby5kZW1vIiwic3ViIjoiUHpUVWp3NHBlXzctWE5rWlBILXJxVHE0MTQ1Z3lDdlRvQmk4V1E5bFBrcW5rbEc1aktvRU5LM21Qb0I1WGY1ZTM5dFRMR2RKWXBMNEJubXFnelpaX0FAa29ubmVjdCIsImtjLmlzQWNjZXNzVG9rZW4iOnRydWUsImtjLmF1dGhvcml6ZWRTY29wZXMiOlsicHJvZmlsZSIsImVtYWlsIiwia29wYW5vL2t3bSIsImtvcGFuby9nYyIsImtvcGFuby9rdnMiLCJvcGVuaWQiXSwia2MuYXV0aG9yaXplZENsYWltcyI6eyJpZF90b2tlbiI6eyJuYW1lIjpudWxsfX0sImtjLmlkZW50aXR5Ijp7ImtjLmkuZG4iOiJKb25hcyBCcmVra2UiLCJrYy5pLmlkIjoiQUFBQUFLd2hxVkJBMCs1SXN4bjdwMU13UkNVQkFBQUFCZ0FBQUJzQUFBQk5VVDA5QUFBQUFBPT0iLCJrYy5pLnVuIjoidXNlcjEiLCJrYy5pLnVzIjoiTVEifSwia2MucHJvdmlkZXIiOiJpZGVudGlmaWVyLWtjIn0.hGRuXvul2kOiALHexwYp5MBEJVwz1YV3ehyM3AOuwCoK2w5sJxdciqqY_TfXCKyO6nAEbYLK3J0CBOjfup_IG0aCZcwzjto8khYlc4ezXkGnFsbJBNQdDGkpHtWnioWx-OJ3cXvY9F8aOvjaq0gw11ZDAcqQl0g7LTbJ9-J_yx0pmy3NGai2JB30Fh1OgSDzYfxWnE0RRgZG-x68e65RXfSBaEGW85OUh4wihxO2zdTGAHJ3Iq_-QAG4yRbXZtLx3ZspG7LNmqG-YE3huy3Rd8u3xrJNhmUOfEnz3x07q7VW0cj9NedX98BAbj3iNvksQsE0oG0J_f_Tu8Ai8VbWB72sJuXZWxANDKdz0BBYLzXhsjXkNByRq9x3zqDVsX-cVHei_XudxEOVRBjhkvW2MmIjcAHNKCKsdar865-gFG9McP4PCcBlY28tC0Cvnzyi83LBfpGRXdl6MJunnUsKQ1C79iCoVI1doK1erFN959Q-TGJfJA3Tr5LNpuGawB5rpe1nDGWvmYhg3uYfNl8uTTyvNgvvejcflEb2DURuXdqABuSiP7RkDWYtzx6mq49G0tRxelBbvyjQ2id2QjmRRdQ6dHEZ2NCJ51b8OFoDJBtxN1CD62TTxa3FUqCdZAPAUR3hHn_69vYq82MR514s-Gb67A6j2PbMPFATQP2UdK8']
        ];
    }

    public function providesHsTokens()
    {
        return [
            'HS256' => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.39jkN-bckg4fbZQEb0xHIxzYL9qI_g4c4WyzEYNHZok'],
            'HS384' => ['eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.np_8QucI7cN6tJo0Fvm3i_eVQEHraSJPRC87yq2UQb77gRWMeeca8zDVIaTlVuZk'],
            'HS512' => ['eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.nZU_gPcMXkWpkCUpJceSxS7lSickF0tTImHhAR949Z-Nt69LgW8G6lid-mqd9B579tYM8C4FN2jdhR2VRMsjtA'],
        ];
    }
}
