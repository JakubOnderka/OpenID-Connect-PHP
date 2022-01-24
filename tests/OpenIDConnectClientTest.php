<?php

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class OpenIDConnectClientTest extends TestCase
{
    /**
     * @return void
     */
    public function testGetRedirectURL()
    {
        $client = new OpenIDConnectClient();

        self::assertSame('http:///', $client->getRedirectURL());

        $_SERVER['SERVER_NAME'] = 'domain.test';
        $_SERVER['REQUEST_URI'] = '/path/index.php?foo=bar&baz#fragment';
        self::assertSame('http://domain.test/path/index.php', $client->getRedirectURL());
    }

    public function testWellKnownUrl()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn('{"issuer":"issuer"}');
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
            ->willReturn('{"issuer":"issuer"}');
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
            ->willReturn('{"issuer":"issuer"}');
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
            ->willReturn('{"issuer":"issuer"}');
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
            ->willReturn('{"issuer":"iss');
        $client->setProviderURL('https://example.com');

        $this->expectException(Jumbojett\JsonException::class);
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
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['decodeJWT', 'getProviderConfigValue', 'verifyJWTsignature'])->getMock();
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

        try {
            $authenticated = $client->authenticate();
            $this->assertTrue($authenticated);
        } catch ( OpenIDConnectClientException $e ) {
            if ( $e->getMessage() === 'Unable to verify JWT claims' ) {
                self::fail( 'OpenIDConnectClientException was thrown when it should not have been.' );
            }
        }
    }

    public function testRequestAuthorization()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['redirect'])->getMock();
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

    public function testRequestAuthorization_additional_scopes()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['redirect'])->getMock();
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
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL', 'getResponseCode'])->getMock();
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
            ->willReturn('{"a":"b"}');
        $this->assertEquals('b', $client->requestUserInfo('a'));
    }

    public function testRequestAuthorization_additional_response_types()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['redirect'])->getMock();
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
            ->willReturn('{"issuer":"https://example.cz"}');
        $client->setProviderURL('https://example.com');
        $this->assertEquals("https://example.cz", $client->getWellKnownIssuer());
    }

    public function testFetchWellKnown_with_custom()
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['fetchURL'])->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration?ahoj=svete'))
            ->willReturn('{"issuer":"https://example.cz"}');
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
                $this->callback(function (array $post) {
                    $this->assertEquals('authorization_code', $post['grant_type']);
                    $this->assertEquals('code', $post['code']);
                    return true;
                }),
                $this->callback(function (array $headers) {
                    $this->assertContains('Authorization: Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=', $headers);
                    return true;
                })
            )->willReturn('{"id_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg","access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg"}');
        $this->assertTrue($client->authenticate());
    }

    private function cleanup()
    {
        $_REQUEST = [];
        $_SESSION = [];
    }
}
