<?php
declare(strict_types=1);

namespace JakubOnderka {
    function setCurlExec(array $curl)
    {
        global $CURL;
        $CURL = $curl;
    }

    // Mock curl_exec method
    function curl_exec($res)
    {
        global $CURL;
        return $CURL['exec'];
    }

    function curl_getinfo($res)
    {
        global $CURL;
        return $CURL['info'];
    }
}

namespace {

    use JakubOnderka\ErrorResponse;
    use JakubOnderka\OpenIDConnectClient;
    use PHPUnit\Framework\TestCase;
    use function JakubOnderka\setCurlExec;

    class FetchUrlTest extends TestCase
    {
        public function testFetchUrl()
        {
            setCurlExec([
                'exec' => '{"sub":"ahoj"}',
                'info' => [
                  'http_code' => 200,
                  'content_type' => 'application/json'
                ],
            ]);

            $client = new OpenIDConnectClient('https://example.com');
            $resp = $client->fetchURL('https://example.com');
            $this->assertEquals(200, $resp->responseCode);
            $this->assertTrue($resp->isSuccess());
            $this->assertEquals('ahoj', $resp->json(true)->sub);
        }

        public function testRequestClientCredentialsToken_error()
        {
            setCurlExec([
                'exec' => '{"error":"error"}',
                'info' => [
                    'http_code' => 401,
                    'content_type' => 'application/json'
                ],
            ]);

            $client = new OpenIDConnectClient("https://example.com", "ahoj", "svete");
            $client->providerConfigParam([
                'token_endpoint' => 'https://example.com/endpoint',
                'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
            ]);
            $this->expectException(ErrorResponse::class);
            $client->requestClientCredentialsToken();
        }
    }
}
