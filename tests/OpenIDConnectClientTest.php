<?php
declare(strict_types=1);

use JakubOnderka\CurlResponse;
use JakubOnderka\OpenIDConnectClient;
use JakubOnderka\OpenIDConnectClientException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class OpenIDConnectClientTest extends TestCase
{
    public function testBase64url()
    {
        $client = new OpenIDConnectClient(); // include

        $binaryString = hash('sha256', '');
        $encoded = JakubOnderka\base64url_encode($binaryString);
        $decoded = JakubOnderka\base64url_decode($encoded);
        $this->assertEquals($binaryString, $decoded);

        foreach (['=', ' ', '+', '/'] as $char) {
            $this->assertThat($char, $this->logicalNot($this->stringContains($encoded)));
        }
    }

    public function testSettersAndGetters()
    {
        $client = new OpenIDConnectClient();

        $client->setLeeway(1234);
        $this->assertEquals(1234, $client->getLeeway());

        $client->setTimeout(1234);
        $this->assertEquals(1234, $client->getTimeout());

        $this->assertNull($client->getClientID());
        $client->setClientID('client-id');
        $this->assertEquals('client-id', $client->getClientID());

        $this->assertNull($client->getClientSecret());
        $client->setClientSecret('client-secret');
        $this->assertEquals('client-secret', $client->getClientSecret());

        $this->assertFalse($client->getAllowImplicitFlow());
        $client->setAllowImplicitFlow(true);
        $this->assertTrue($client->getAllowImplicitFlow());

        $client->setRedirectURL('http://localhost:8080/users/login');
    }

    /**
     * @return void
     */
    public function testGetRedirectURL()
    {
        $client = new OpenIDConnectClient();

        $this->assertSame('http:///', $client->getRedirectURL());

        $_SERVER['SERVER_NAME'] = 'domain.test';
        $_SERVER['REQUEST_URI'] = '/path/index.php?foo=bar&baz#fragment';
        $this->assertSame('http://domain.test/path/index.php', $client->getRedirectURL());
    }

    public function testWellKnownUrl()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"issuer"}'));
        $client->setProviderURL('https://example.com');
        $this->assertEquals('issuer', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_withSlash()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"issuer"}'));
        $client->setProviderURL('https://example.com/');
        $this->assertEquals('issuer', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_full()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"issuer"}'));
        $client->setProviderURL('https://example.com/.well-known/openid-configuration');
        $this->assertEquals('issuer', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_custom()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration?ahoj=svete'))
            ->willReturn(new CurlResponse('{"issuer":"issuer"}'));
        $client->setWellKnownConfigParameters(['ahoj' => 'svete']);
        $client->setProviderURL('https://example.com');
        $this->assertEquals('issuer', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_invalidJson_throwException()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"iss'));
        $client->setProviderURL('https://example.com');

        $this->expectException(JakubOnderka\JsonException::class);
        $client->getWellKnownIssuer();
    }

    public function testAuthenticateDoesNotThrowExceptionIfClaimsIsMissingNonce()
    {
        $this->cleanup();

        $fakeClaims = new \StdClass();
        $fakeClaims->iss = 'fake-issuer';
        $fakeClaims->aud = 'fake-client-id';
        $fakeClaims->nonce = null;

        $_REQUEST['id_token'] = 'abc.123.xyz';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['decodeJWT', 'getProviderConfigValue', 'verifyJWTsignature'])
            ->getMock();
        $client->method('decodeJWT')->willReturn($fakeClaims);
        $client->method('getProviderConfigValue')->with('jwks_uri')->willReturn(true);
        $client->method('verifyJWTsignature')->willReturn(true);

        $client->setClientID('fake-client-id');
        $client->setIssuer('fake-issuer');
        $client->setIssuerValidator(function() {
            return true;
        });
        $client->setAllowImplicitFlow(true);
        $client->setProviderURL('https://jwt.io/');

        $authenticated = $client->authenticate();
        $this->assertTrue($authenticated);
    }

    public function testRequestAuthorization()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->getMock();
        $client->method('commitSession')->willReturn(true);
        $client->method('redirect')->with(
            $this->callback(function (string $value): bool {
                $parsed = parse_url($value);
                $this->assertEquals('https', $parsed['scheme']);
                $this->assertEquals('example.com', $parsed['host']);
                parse_str($parsed['query'], $query);
                $this->assertEquals('code', $query['response_type']);
                $this->assertEquals('id', $query['client_id']);
                $this->assertNotEmpty($query['nonce']);
                $this->assertNotEmpty($query['state']);
                $this->assertNotEquals($query['nonce'], $query['state']);
                $this->assertEquals('openid', $query['scope']);
                return true;
            })
        );
        $client->setClientID('id');
        $client->providerConfigParam([
            'authorization_endpoint' => 'https://example.com',
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestAuthorization_codeChallenge()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->getMock();
        $client->method('commitSession')->willReturn(true);
        $client->method('redirect')->with(
            $this->callback(function (string $value) {
                $parsed = parse_url($value);
                parse_str($parsed['query'], $query);
                $this->assertEquals('plain', $query['code_challenge_method']);
                $this->assertGreaterThanOrEqual(43, strlen($query['code_challenge']));
                $this->assertLessThanOrEqual(128, strlen($query['code_challenge']));
                return true;
            })
        );
        $client->setClientID('id');
        $client->setCodeChallengeMethod('plain');
        $client->providerConfigParam([
            'authorization_endpoint' => 'https://example.com',
            'code_challenge_methods_supported' => ['plain', 'S256'],
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestAuthorization_codeChallengeS256()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->getMock();
        $client->method('commitSession')->willReturn(true);
        $client->method('redirect')->with(
            $this->callback(function (string $value) {
                $parsed = parse_url($value);
                parse_str($parsed['query'], $query);
                $this->assertEquals('S256', $query['code_challenge_method']);
                $this->assertGreaterThanOrEqual(43, strlen($query['code_challenge']));
                $this->assertLessThanOrEqual(128, strlen($query['code_challenge']));
                return true;
            })
        );
        $client->setClientID('id');
        $client->setCodeChallengeMethod('S256');
        $client->providerConfigParam([
            'authorization_endpoint' => 'https://example.com',
            'code_challenge_methods_supported' => ['plain', 'S256'],
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestAuthorization_additional_scopes()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->getMock();
        $client->method('commitSession')->willReturn(true);
        $client->method('redirect')->with(
            $this->callback(function ($value) {
                $parsed = parse_url($value);
                $this->assertEquals('https', $parsed['scheme']);
                $this->assertEquals('example.com', $parsed['host']);
                parse_str($parsed['query'], $query);
                $this->assertEquals('code', $query['response_type']);
                $this->assertEquals('id', $query['client_id']);
                $this->assertNotEmpty($query['nonce']);
                $this->assertNotEmpty($query['state']);
                $this->assertNotEquals($query['nonce'], $query['state']);
                $this->assertEquals('custom openid', $query['scope']);
                return true;
            })
        );
        $client->addScope('custom');
        $client->setClientID('id');
        $client->providerConfigParam([
            'authorization_endpoint' => 'https://example.com',
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestUserInfo()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL', 'getResponseCode'])
            ->getMock();
        $client->setAccessToken('aa.bb.cc');
        $client->providerConfigParam([
            'userinfo_endpoint' => 'https://example.com',
        ]);
        $client->method('getResponseCode')->willReturn(200);
        $client->method('fetchURL')
            ->with(
                $this->equalTo('https://example.com?schema=openid'),
                $this->equalTo(null),
                $this->callback(function (array $a) {
                    $this->assertContains('Authorization: Bearer aa.bb.cc', $a);
                    return true;
                })
            )
            ->willReturn(new CurlResponse('{"a":"b"}'));
        $this->assertEquals('b', $client->requestUserInfo('a'));
    }

    public function testRequestAuthorization_additional_response_types()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->getMock();
        $client->method('commitSession')->willReturn(true);
        $client->method('redirect')->with(
            $this->callback(function ($value) {
                $parsed = parse_url($value);
                $this->assertEquals('https', $parsed['scheme']);
                $this->assertEquals('example.com', $parsed['host']);
                parse_str($parsed['query'], $query);
                $this->assertEquals('custom', $query['response_type']);
                $this->assertEquals('id', $query['client_id']);
                $this->assertNotEmpty($query['nonce']);
                $this->assertNotEmpty($query['state']);
                $this->assertNotEquals($query['nonce'], $query['state']);
                $this->assertEquals('openid', $query['scope']);
                return true;
            })
        );
        $client->setResponseTypes('custom');
        $client->setClientID('id');
        $client->providerConfigParam([
            'authorization_endpoint' => 'https://example.com',
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testFetchWellKnown()
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.cz"}'));
        $client->setProviderURL('https://example.com');
        $this->assertEquals("https://example.cz", $client->getWellKnownIssuer());
    }

    public function testFetchWellKnown_with_custom()
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration?ahoj=svete'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.cz"}'));
        $client->setProviderURL('https://example.com');
        $client->setWellKnownConfigParameters(['ahoj' => 'svete']);
        $this->assertEquals("https://example.cz", $client->getWellKnownIssuer());
    }

    public function testRequestTokensClientSecretBasic()
    {
        $this->cleanup();

        $_REQUEST['id_token'] = 'abc.123.xyz';
        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL', 'verifyJWTsignature', 'verifyJWTclaims'])->getMock();
        $client->method('verifyJWTsignature')->willReturn(true);
        $client->method('verifyJWTclaims')->willReturn(true);
        $client->setClientID('client-id');
        $client->setClientSecret('client-secret');
        $client->providerConfigParam([
            'token_endpoint' => 'https://example.com',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);
        $client->method('fetchURL')
            ->with(
                $this->equalTo('https://example.com'),
                $this->callback(function (array $post): bool {
                    $this->assertEquals('authorization_code', $post['grant_type']);
                    $this->assertEquals('code', $post['code']);
                    return true;
                }),
                $this->callback(function (array $headers): bool {
                    $this->assertContains('Authorization: Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=', $headers);
                    return true;
                })
            )->willReturn(new CurlResponse('{"id_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg","access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg"}'));
        $this->assertTrue($client->authenticate());
    }

    public function testRefreshToken()
    {
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->providerConfigParam([
            'token_endpoint' => 'https://example.com',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);
        $client->setClientID('client-id');
        $client->setClientSecret('client-secret');
        $client->method('fetchURL')->with(
            $this->equalTo('https://example.com'),
            $this->callback(function (array $post): bool {
                $this->assertEquals('refresh_token', $post['grant_type']);
                return true;
            }), $this->callback(function (array $headers): bool {
                $this->assertContains('Authorization: Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=', $headers);
                return true;
            })
        )->willReturn(new CurlResponse('{"access_token": "access_token", "refresh_token": "refresh_token"}'));
        $token = $client->refreshToken("token");
        $this->assertTrue(isset($token->access_token));
        $this->assertTrue(isset($token->refresh_token));
        $this->assertNotEmpty($client->getAccessToken());
        $this->assertNotEmpty($client->getRefreshToken());
    }

    public function testRequestTokensClientSecretJwt()
    {
        $this->cleanup();

        $_REQUEST['id_token'] = 'abc.123.xyz';
        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL', 'verifyJWTsignature', 'verifyJWTclaims'])->getMock();
        $client->method('verifyJWTsignature')->willReturn(true);
        $client->method('verifyJWTclaims')->willReturn(true);
        $client->setTokenAuthenticationMethod('client_secret_jwt');
        $client->setClientID('client-id');
        $client->setClientSecret('client-secret');
        $client->providerConfigParam([
            'token_endpoint' => 'https://example.com',
            'token_endpoint_auth_methods_supported' => ['client_secret_jwt'],
        ]);
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com'), $this->callback(function (array $post) use ($client) {
                $this->assertEquals('authorization_code', $post['grant_type']);
                $this->assertEquals('code', $post['code']);
                $this->assertEquals('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $post['client_assertion_type']);
                $this->assertTrue($client->verifyJwtSignature($post['client_assertion']));
                return true;
            }))->willReturn(new CurlResponse('{"id_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg","access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg"}'));
        $this->assertTrue($client->authenticate());
    }

    public function testRequestTokensClientClientSecretPost()
    {
        $this->cleanup();

        $_REQUEST['id_token'] = 'abc.123.xyz';
        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL', 'verifyJWTsignature', 'verifyJWTclaims'])->getMock();
        $client->method('verifyJWTsignature')->willReturn(true);
        $client->method('verifyJWTclaims')->willReturn(true);
        $client->setTokenAuthenticationMethod('client_secret_post');
        $client->setClientID('client-id');
        $client->setClientSecret('client-secret');
        $client->providerConfigParam([
            'token_endpoint' => 'https://example.com',
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
        ]);
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com'), $this->callback(function (array $post): bool {
                $this->assertEquals('authorization_code', $post['grant_type']);
                $this->assertEquals('code', $post['code']);
                $this->assertEquals('client-id', $post['client_id']);
                $this->assertEquals('client-secret', $post['client_secret']);
                return true;
            }))->willReturn(new CurlResponse('{"id_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg","access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg"}'));
        $this->assertTrue($client->authenticate());
    }

    private function cleanup()
    {
        $_REQUEST = [];
        $_SESSION = [];
    }
}
