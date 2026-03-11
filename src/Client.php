<?php
declare(strict_types=1);

namespace AlfaID;

use AlfaID\Domain\DTO\AccessToken;
use AlfaID\Domain\DTO\AlfaUser;
use AlfaID\Domain\DTO\ApiResponseWrapper;
use AlfaID\Domain\DTO\AuthCode;
use AlfaID\Infrastructure\Http\Tls\CertificateBundle;

use Exception;
use JsonException;
use RuntimeException;

final class Client {
    private string $client_id;
    private string $client_secret;
    private string $default_redirect_uri;
    private CertificateBundle $certificate;
    private bool $sandbox;

    public function __construct(string $client_id, string $default_redirect_uri, CertificateBundle $certificate, ?string $client_secret = null, bool $sandbox = true) {
        $this->client_id = $client_id;
        $this->default_redirect_uri = $default_redirect_uri;
        $this->certificate = $certificate;
        $this->sandbox = $sandbox;

        if ($client_secret) {
            $this->client_secret = $client_secret;
        }
        else {
            $this->client_secret = self::getSecret($client_id, $certificate, $sandbox);
        }
    }

    public function getLinkForAuth (string $state, string $scope = "openid", ?string $redirect_uri = null, bool $reset_consent = false): string {
        $host = $this->sandbox ?
                    "https://id-sandbox.alfabank.ru" :
                    "https://id.alfabank.ru";

        $params = [
            "response_type" => "code",
            "client_id"     => $this->client_id,
            "redirect_uri"  => $redirect_uri ?: $this->default_redirect_uri,
            "scope"         => $scope,
            "state"         => $state
        ];

        if ($reset_consent) $params["prompt"] = "consent";

        $query = http_build_query($params, encoding_type: PHP_QUERY_RFC3986);

        return $host . "/oidc/authorize?" . $query;
    }

    private static function getSecret (string $client_id, CertificateBundle $cert, bool $sandbox):string {
        $client_id_url = rawurlencode($client_id);
        $host = $sandbox ?
                    "https://sandbox.alfabank.ru/oidc/clients/$client_id_url/client-secret" :
                    "https://baas.alfabank.ru/oidc/clients/$client_id_url/client-secret";

        $response = self::sendRequest($host, "POST", $cert, null, ['Accept: application/json']);

        if ($response->error || $response->code !== 200) {
            throw new RuntimeException("Can't get the client's secret: HTTP {$response->code}" . ($response->error ? " ({$response->error})" : ''), $response->code);
        }

        if ($response->data === null || $response->data === '') {
            throw new RuntimeException("Can't get the client's secret: empty response");
        }

        try {
            $data = json_decode($response->data, flags: JSON_THROW_ON_ERROR);
        }
        catch (JsonException $e) {
            throw new RuntimeException("Can't get the client's secret: invalid JSON response", 0, $e);
        }

        if (!is_object($data) || !isset($data->clientSecret) || !is_string($data->clientSecret) || trim($data->clientSecret) === '') {
            throw new RuntimeException("Can't get the client's secret: invalid response structure");
        }

        return $data->clientSecret;
    }

    public function processAuthCode ():AuthCode {
        $code  = filter_input(INPUT_GET, 'code',  FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);
        $error = filter_input(INPUT_GET, 'error', FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);
        $state = filter_input(INPUT_GET, 'state', FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);

        $code  = is_string($code)  ? trim($code)  : null;
        $error = is_string($error) ? trim($error) : null;
        $state = is_string($state) ? trim($state) : null;

        $code  = $code === ''  ? null : $code;
        $error = $error === '' ? null : $error;
        $state = $state === '' ? null : $state;

        if ($code !== null  && strlen($code)  > 64) {
            throw new RuntimeException("Failed to process auth code: code value is too long");
        }

        if ($error !== null && strlen($error) > 64) {
            throw new RuntimeException("Failed to process auth code: error value is too long");
        }

        if ($state === null) {
            throw new RuntimeException("Failed to process auth code: state is missing");
        }

        if (strlen($state) > 64) {
            throw new RuntimeException("Failed to process auth code: state value is too long");
        }

        if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $state)) {
            throw new RuntimeException("Failed to process auth code: state value is invalid");
        }

        if ($code !== null && !preg_match('/^[A-Za-z0-9_-]{1,64}$/', $code)) {
            throw new RuntimeException("Failed to process auth code: code value is invalid");
        }

        if ($error !== null && !preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $error)) {
            throw new RuntimeException("Failed to process auth code: error value is invalid");
        }

        if ($code !== null && $error !== null) {
            throw new RuntimeException("Failed to process auth code: response contains both code and error");
        }

        if ($code === null && $error === null) {
            throw new RuntimeException("Failed to process auth code: response is empty");
        }

        return new AuthCode($state, $code, $error);
    }

    public function getToken (AuthCode $code, ?string $redirect_uri = null):?AccessToken {
        if ($code->error) return null;

        $host = $this->sandbox ?
                    "https://sandbox.alfabank.ru/oidc/token" :
                    "https://baas.alfabank.ru/oidc/token";

        $uri = $redirect_uri ?? $this->default_redirect_uri;

        $body = http_build_query([
            "grant_type" => "authorization_code",
            "code" => $code->code,
            "client_id" => $this->client_id,
            "client_secret" => $this->client_secret,
            "redirect_uri" => $uri
        ]);

        $req = self::sendRequest($host, "POST", $this->certificate, $body, [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ]);

        if ($req->error || $req->code !== 200 || !$req->data) return null;

        try {
            $res = json_decode($req->data, null, 512, JSON_THROW_ON_ERROR);

            if (
                isset($res->access_token) &&
                isset($res->refresh_token) &&
                isset($res->token_type) &&
                isset($res->expires_in) &&
                isset($res->id_token)
            ) {
                return new AccessToken(
                    $res->access_token,
                    $res->refresh_token,
                    $res->token_type,
                    time() + $res->expires_in,
                    $res->id_token
                );
            }

            return null;
        }
        catch (Exception $e) {
            return null;
        }
    }

    public function refreshToken (AccessToken $token):?AccessToken {
        $host = $this->sandbox ?
                    "https://sandbox.alfabank.ru/oidc/token" :
                    "https://baas.alfabank.ru/oidc/token";

        $body = http_build_query([
            "grant_type" => "refresh_token",
            "refresh_token" => $token->refresh_token,
            "client_id" => $this->client_id,
            "client_secret" => $this->client_secret
        ]);

        $req = self::sendRequest($host, "POST", $this->certificate, $body, [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ]);

        if ($req->error || $req->code !== 200 || !$req->data) return null;

        try {
            $res = json_decode($req->data, null, 512, JSON_THROW_ON_ERROR);

            if (
                isset($res->access_token) &&
                isset($res->refresh_token) &&
                isset($res->token_type) &&
                isset($res->expires_in)
            ) {
                return new AccessToken(
                    $res->access_token,
                    $res->refresh_token,
                    $res->token_type,
                    time() + $res->expires_in,
                    $token->id_token
                );
            }

            return null;
        }
        catch (Exception $e) {
            return null;
        }
    }

    public function getUserInfo (AccessToken $token):AlfaUser|null {
        $host = $this->sandbox ? "https://sandbox.alfabank.ru/oidc/userinfo" : "https://baas.alfabank.ru/oidc/userinfo";

        $req = self::sendRequest($host, "GET", $this->certificate, null, [
            "Authorization: Bearer $token->access_token",
            "Accept: application/jwt"
        ]);

        if ($req->error || $req->code !== 200 || !$req->data) return null;

        $data = explode(".", $req->data);

        if (count($data) !== 3) return null;

        try {
            $decodedData = strtr($data[1], '-_', '+/');
            $pad = strlen($decodedData) % 4;
            if ($pad) $decodedData .= str_repeat('=', 4 - $pad);
            $decodedData = base64_decode($decodedData, true);
            if ($decodedData === false) return null;
            
            $userData = json_decode($decodedData, null, 512, JSON_THROW_ON_ERROR);

            if (
                !isset($userData->given_name) ||
                !isset($userData->family_name) ||
                !isset($userData->phone_number)
            ) {
                return null;
            }

            return new AlfaUser(
                $userData->given_name,
                $userData->family_name,
                $userData->middle_name,
                $userData->email,
                $userData->gender,
                $userData->birthdate,
                $userData->phone_number,
                $userData->citizenship,
                $userData->package_name,
                $userData->package_code
            );
        }
        catch (Exception $e) {
            return null;
        }
    }

    private static function sendRequest (
        string $host,
        string $method = "GET",
        ?CertificateBundle $certificate = null,
        $body = null,
        ?array $headers = null,
        int $timeout = 10
    ):ApiResponseWrapper {
        $ch = curl_init($host);

        if ($ch === false) return new ApiResponseWrapper(0, null, "cURL init error");

        $method_normalized = strtoupper($method);

        $curl_opt = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT        => $timeout
        ];

        if ($headers) $curl_opt[CURLOPT_HTTPHEADER] = $headers;

        if ($method_normalized === "POST") {
            $curl_opt[CURLOPT_POST] = true;
            $curl_opt[CURLOPT_POSTFIELDS] = $body;
        }
        elseif ($method_normalized !== "GET") {
            $curl_opt[CURLOPT_CUSTOMREQUEST] = $method_normalized;
            $curl_opt[CURLOPT_POSTFIELDS] = $body;
        }

        if ($certificate) {
            $curl_opt[CURLOPT_SSLCERT]        = $certificate->file_path;
            $curl_opt[CURLOPT_SSLKEY]         = $certificate->secret_file_path;
            $curl_opt[CURLOPT_SSL_VERIFYPEER] = true;
            $curl_opt[CURLOPT_SSL_VERIFYHOST] = 2;

            if ($certificate->chain_file_path) $curl_opt[CURLOPT_CAINFO] = $certificate->chain_file_path;
            if ($certificate->pass) $curl_opt[CURLOPT_KEYPASSWD] = $certificate->pass;
        }

        curl_setopt_array($ch, $curl_opt);

        $res = curl_exec($ch);
        $err = curl_error($ch);
        $errno = curl_errno($ch);
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return new ApiResponseWrapper(
            $code,
            $res === false ? null : $res,
            $err !== '' ? $err : null,
            $errno
        );
    }
}