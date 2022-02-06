<?php
declare(strict_types=1);

use JakubOnderka\CurlResponse;
use JakubOnderka\OpenIDConnectClient;
use JakubOnderka\Jwt;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class OpenIDConnectClientTest extends TestCase
{
    public function testBase64url()
    {
        $client = new OpenIDConnectClient('https://example.com'); // include

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
        $client = new OpenIDConnectClient('https://example.com');

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
        $client = new OpenIDConnectClient('https://example.com');

        $this->cleanup();

        $this->assertSame('http:///', $client->getRedirectURL());

        $_SERVER['SERVER_NAME'] = 'domain.test';
        $_SERVER['REQUEST_URI'] = '/path/index.php?foo=bar&baz#fragment';
        $this->assertSame('http://domain.test/path/index.php', $client->getRedirectURL());
    }

    public function testWellKnownUrl()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.com"}'));
        $client->setIssuer('https://example.com');
        $this->assertEquals('https://example.com', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_withSlash()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com/'])
            ->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.com"}'));
        $client->setIssuer('https://example.com/');
        $this->assertEquals('https://example.com', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_full()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com/.well-known/openid-configuration'])
            ->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.com"}'));
        $client->setIssuer('https://example.com');
        $this->assertEquals('https://example.com', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_custom()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration?ahoj=svete'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.com"}'));
        $client->setWellKnownConfigParameters(['ahoj' => 'svete']);
        $this->assertEquals('https://example.com', $client->getWellKnownIssuer());
    }

    public function testWellKnownUrl_invalidJson_throwException()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"iss'));

        $this->expectException(JakubOnderka\JsonException::class);
        $client->getWellKnownIssuer();
    }

    public function testProviderUrl_fromConstructor()
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs(['https://example.com/.well-known/openid-configuration'])
            ->setMethods(['fetchURL'])
            ->getMock();
        $client->expects($this->once())
            ->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.com/"}'));

        $this->assertEquals('https://example.com/', $client->getIssuer());
        $this->assertEquals('https://example.com/', $client->getProviderURL());
        $client->getWellKnownIssuer();
    }

    public function testWellKnownUrl_invalidIssuer()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"iss"}'));

        $this->expectException(JakubOnderka\OpenIDConnectClientException::class);
        $this->expectExceptionMessage('Invalid OpenID Provider Metadata returned, expected issuer `https://example.com`, `iss` provided.');
        $client->getWellKnownIssuer();
    }

    public function testRequestAuthorization()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->setConstructorArgs(['https://example.com'])
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
            'pushed_authorization_request_endpoint' => false,
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestAuthorization_codeChallenge()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->setConstructorArgs(['https://example.com'])
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
            'pushed_authorization_request_endpoint' => false,
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestAuthorization_codeChallengeS256()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->setConstructorArgs(['https://example.com'])
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
            'pushed_authorization_request_endpoint' => false,
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestAuthorization_additionalScopes()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->setConstructorArgs(['https://example.com'])
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
            'pushed_authorization_request_endpoint' => false,
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestAuthorization_par()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession', 'fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->method('commitSession')->willReturn(true);

        $client->expects($this->once())->method('fetchURL')
            ->with(
                $this->equalTo('https://example.com/par'),
                $this->callback(function (array $value) use ($client): bool {
                    $this->assertArrayHasKey('request', $value);
                    $this->assertEquals('id', $value['client_id']);
                    $this->assertTrue($client->verifyJwtSignature(new Jwt($value['request'])));
                    return true;
                })
            )
            ->willReturn(new CurlResponse('{"request_uri":"urn:ietf:params:oauth:request_uri:bwc4JK-ESC0w8acc191e-Y1LTC2"}'));

        $client->expects($this->once())->method('redirect')->with(
            $this->callback(function (string $value): bool {
                $parsed = parse_url($value);
                parse_str($parsed['query'], $query);
                $this->assertEquals('id', $query['client_id']);
                $this->assertEquals('urn:ietf:params:oauth:request_uri:bwc4JK-ESC0w8acc191e-Y1LTC2', $query['request_uri']);
                return true;
            })
        );
        $client->setClientID('id');
        $client->setClientSecret('secret');
        $client->providerConfigParam([
            'authorization_endpoint' => 'https://example.com',
            'pushed_authorization_request_endpoint' => 'https://example.com/par',
            'token_endpoint' => 'https://example.com/token',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testRequestUserInfo()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL', 'getIdToken'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->setAccessToken('aa.bb.cc');
        $client->providerConfigParam([
            'userinfo_endpoint' => 'https://example.com',
        ]);
        $client->method('getIdToken')->willReturn(Jwt::createHmacSigned([
            'sub' => 'sub',
        ], 'HS256', 'secret'));
        $client->method('fetchURL')
            ->with(
                $this->equalTo('https://example.com?schema=openid'),
                $this->equalTo(null),
                $this->callback(function (array $a) {
                    $this->assertContains('Authorization: Bearer aa.bb.cc', $a);
                    return true;
                })
            )
            ->willReturn(new CurlResponse('{"a":"b","sub":"sub"}'));
        $this->assertEquals('b', $client->requestUserInfo('a'));
    }

    public function testRequestUserInfo_jwtTokenAsResponse()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL', 'getIdToken'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->setAccessToken('aa.bb.cc');
        $client->setClientSecret('secret');
        $client->providerConfigParam([
            'userinfo_endpoint' => 'https://example.com',
        ]);
        $client->method('getIdToken')->willReturn(Jwt::createHmacSigned([
            'sub' => 'sub',
        ], 'HS256', 'secret'));
        $jwtResponse = (string)Jwt::createHmacSigned(['sub' => 'sub', 'a' => 'b'], 'HS256', 'secret');
        $client->method('fetchURL')
            ->with(
                $this->equalTo('https://example.com?schema=openid'),
                $this->equalTo(null),
                $this->callback(function (array $a) {
                    $this->assertContains('Authorization: Bearer aa.bb.cc', $a);
                    return true;
                })
            )
            ->willReturn(new CurlResponse($jwtResponse, 200, 'application/jwt'));
        $this->assertEquals('b', $client->requestUserInfo('a'));
    }

    public function testRequestAuthorization_additional_responseTypes()
    {
        $this->cleanup();

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['redirect', 'commitSession'])
            ->setConstructorArgs(['https://example.com'])
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
            'pushed_authorization_request_endpoint' => false,
        ]);
        $this->assertFalse($client->authenticate());
    }

    public function testFetchWellKnown()
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();

        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.com"}'));
        $this->assertEquals("https://example.com", $client->getWellKnownIssuer());
    }

    public function testFetchWellKnown_with_custom()
    {
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();

        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com/.well-known/openid-configuration?ahoj=svete'))
            ->willReturn(new CurlResponse('{"issuer":"https://example.com"}'));
        $client->setWellKnownConfigParameters(['ahoj' => 'svete']);
        $this->assertEquals("https://example.com", $client->getWellKnownIssuer());
    }

    public function testRequestTokens_clientSecretBasic()
    {
        $this->cleanup();

        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL', 'verifyJwtSignature', 'validateIdToken'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();

        $client->method('verifyJwtSignature')->willReturn(true);
        $client->method('validateIdToken')->willReturn(true);
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
            )->willReturn($this->authorizationCodeResponse());
        $this->assertTrue($client->authenticate());
    }

    public function testAuthenticate_differentState()
    {
        $this->cleanup();

        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state_different';
        $_SESSION['openid_connect_state'] = 'state';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();

        $client->setClientID('client-id');
        $client->setClientSecret('client-secret');
        $client->providerConfigParam([
            'token_endpoint' => 'https://example.com',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]);
        $client->method('fetchURL')->willReturn($this->authorizationCodeResponse());

        $this->expectExceptionMessage('State from session is different than provided state from request');
        $client->authenticate();
    }

    public function testRefreshToken()
    {
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();

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

    public function testRequestTokens_clientSecretJwtAuth_supported()
    {
        $this->cleanup();

        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL', 'verifyJwtSignature', 'validateIdToken'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->method('verifyJwtSignature')->willReturn(true);
        $client->method('validateIdToken')->willReturn(true);
        $client->setAuthenticationMethod('client_secret_jwt');
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
                $this->assertTrue($client->verifyJwtSignature(new Jwt($post['client_assertion'])));
                return true;
            }))->willReturn($this->authorizationCodeResponse());
        $this->assertTrue($client->authenticate());
    }

    public function testRequestTokens_clientSecretJwtAuth_notSupported()
    {
        $this->cleanup();

        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL', 'verifyJwtSignature', 'validateIdToken'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();
        $client->method('verifyJwtSignature')->willReturn(true);
        $client->method('validateIdToken')->willReturn(true);
        $client->setAuthenticationMethod('client_secret_post');
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
            }))->willReturn($this->authorizationCodeResponse());
        $this->assertTrue($client->authenticate());

        $this->assertEquals('John Doe', $client->getVerifiedClaims()->name);
        $this->assertEquals('John Doe', $client->getVerifiedClaims('name'));
        $this->assertNull($client->getVerifiedClaims('unknwon'));
    }

    public function testRequestTokens_codeChallengeMethod()
    {
        $this->cleanup();

        $_REQUEST['code'] = 'code';
        $_REQUEST['state'] = 'state';
        $_SESSION['openid_connect_state'] = 'state';
        $_SESSION['openid_connect_code_verifier'] = 'verifier';

        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setMethods(['fetchURL', 'verifyJwtSignature', 'validateIdToken'])
            ->setConstructorArgs(['https://example.com'])
            ->getMock();

        $client->method('verifyJwtSignature')->willReturn(true);
        $client->method('validateIdToken')->willReturn(true);
        $client->setClientID('client-id');
        $client->setClientSecret('client-secret');
        $client->setCodeChallengeMethod('S256');
        $client->providerConfigParam([
            'token_endpoint' => 'https://example.com',
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
        ]);
        $client->method('fetchURL')
            ->with($this->equalTo('https://example.com'), $this->callback(function (array $post): bool {
                $this->assertEquals('authorization_code', $post['grant_type']);
                $this->assertEquals('code', $post['code']);
                $this->assertEquals('client-id', $post['client_id']);
                $this->assertEquals('verifier', $post['code_verifier']);
                return true;
            }))->willReturn($this->authorizationCodeResponse());
        $this->assertTrue($client->authenticate());
    }

    private function authorizationCodeResponse(): CurlResponse
    {
        $response = '{"id_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg","access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.he0ErCNloe4J7Id0Ry2SEDg09lKkZkfsRiGsdX_vgEg"}';
        return new CurlResponse($response);
    }

    private function cleanup()
    {
        $_REQUEST = [];
        $_SESSION = [];

        $_SERVER['SERVER_NAME'] = '';
        $_SERVER['REQUEST_URI'] = '';
    }
}
