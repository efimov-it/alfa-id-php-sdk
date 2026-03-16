<?php
declare(strict_types=1);

namespace AlfaID;

use AlfaID\Domain\DTO\AccessToken;
use AlfaID\Domain\DTO\AlfaUser;
use AlfaID\Domain\DTO\ApiResponseWrapper;
use AlfaID\Domain\DTO\AuthCode;
use AlfaID\Infrastructure\Http\Tls\SecurityBundle;
use Exception;
use JsonException;
use RuntimeException;

final class Client {
    private string $client_id;
    private string $client_secret;
    private string $default_redirect_uri;
    private SecurityBundle $security_bundle;
    private bool $sandbox;

    public function __construct(string $client_id, string $default_redirect_uri, SecurityBundle $security_bundle, ?string $client_secret = null, bool $sandbox = true) {
        $this->client_id = $client_id;
        $this->default_redirect_uri = $default_redirect_uri;
        $this->security_bundle = $security_bundle;
        $this->sandbox = $sandbox;

        if ($client_secret) {
            $this->client_secret = $client_secret;
        }
        else {
            try {
                $this->client_secret = self::getNewClientSecret($client_id, $security_bundle, $sandbox);
            } 
            catch (Exception $e) {
                throw new RuntimeException("Failed to initialize Alfa ID instance: " . $e->getMessage(), 0, $e);
            }
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

    private static function getNewClientSecret (string $client_id, SecurityBundle $security_bundle, bool $sandbox):string {
        $client_id_url = rawurlencode($client_id);
        $host = $sandbox ?
                    "https://sandbox.alfabank.ru/oidc/clients/$client_id_url/client-secret" :
                    "https://baas.alfabank.ru/oidc/clients/$client_id_url/client-secret";

        $response = self::sendRequest($host, "POST", $security_bundle, null, ['Accept: application/json']);

        if ($response->error || $response->code !== 200) {
            throw new RuntimeException("Failed to get the client's secret: HTTP {$response->code}" . ($response->error ? " ({$response->error})" : ''), $response->code);
        }

        if ($response->data === null || $response->data === '') {
            throw new RuntimeException("Failed to get the client's secret: empty response");
        }

        try {
            $data = json_decode($response->data, flags: JSON_THROW_ON_ERROR);
        }
        catch (JsonException $e) {
            throw new RuntimeException("Failed to get the client's secret: invalid JSON response", 0, $e);
        }

        if (!is_object($data) || !isset($data->clientSecret) || !is_string($data->clientSecret) || trim($data->clientSecret) === '') {
            throw new RuntimeException("Failed to get the client's secret: invalid response structure");
        }

        return $data->clientSecret;
    }

    public function getClientSecret ():string {
        return $this->client_secret;
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

    public function getToken (AuthCode $code, ?string $redirect_uri = null):AccessToken {
        if ($code->error !== null) {
            throw new RuntimeException("Failed to get token: auth response contains error: {$code->error}");
        }

        if ($code->code === null || $code->code === '') {
            throw new RuntimeException("Failed to get token: auth code is missing");
        }

        $host = $this->sandbox ?
                    "https://sandbox.alfabank.ru/oidc/token" :
                    "https://baas.alfabank.ru/oidc/token";

        $uri = $redirect_uri ?? $this->default_redirect_uri;
        $uri = is_string($uri) ? trim($uri) : null;

        if ($uri === null || $uri === '') {
            throw new RuntimeException("Failed to get token: redirect URI is missing");
        }

        $body = http_build_query([
            "grant_type" => "authorization_code",
            "code" => $code->code,
            "client_id" => $this->client_id,
            "client_secret" => $this->client_secret,
            "redirect_uri" => $uri
        ]);

        $response = self::sendRequest($host, "POST", $this->security_bundle, $body, [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ]);

        if ($response->error || $response->code !== 200) {
            throw new RuntimeException("Failed to get token: HTTP {$response->code}" . ($response->error ? " ({$response->error})" : ''), $response->code);
        }
            
        if ($response->data === null || $response->data === '') {
            throw new RuntimeException("Failed to get token: empty response");
        }

        try {
            $data = json_decode($response->data, flags: JSON_THROW_ON_ERROR);
        }
        catch (JsonException $e) {
            throw new RuntimeException("Failed to get token: invalid JSON response", 0, $e);
        }

        if (
            !is_object($data) ||
            !isset($data->access_token, $data->refresh_token, $data->token_type, $data->expires_in, $data->id_token) ||
            !is_string($data->access_token) || $data->access_token === '' ||
            !is_string($data->refresh_token) || $data->refresh_token === '' ||
            !is_string($data->token_type) || $data->token_type === '' ||
            !is_string($data->id_token) || $data->id_token === ''
        ) {
            throw new RuntimeException("Failed to get token: invalid JSON structure");
        }

        $expiresIn = filter_var($data->expires_in, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1],
        ]);

        if ($expiresIn === false) {
            throw new RuntimeException("Failed to get token: expires_in is invalid");
        }

        return new AccessToken(
            $data->access_token,
            $data->refresh_token,
            $data->token_type,
            time() + $expiresIn,
            $data->id_token
        );
    }

    public function refreshToken (AccessToken $token):AccessToken {
        $refresh_token = trim($token->refresh_token);
        if ($refresh_token === "") {
            throw new RuntimeException("Failed to refresh token: refresh token is missing");
        }

        $host = $this->sandbox ?
                    "https://sandbox.alfabank.ru/oidc/token" :
                    "https://baas.alfabank.ru/oidc/token";

        $body = http_build_query([
            "grant_type" => "refresh_token",
            "refresh_token" => $refresh_token,
            "client_id" => $this->client_id,
            "client_secret" => $this->client_secret
        ]);

        $response = self::sendRequest($host, "POST", $this->security_bundle, $body, [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ]);

        if ($response->error || $response->code !== 200) {
            throw new RuntimeException("Failed to refresh token: HTTP {$response->code}" . ($response->error ? " ({$response->error})" : ''), $response->code);
        }

        if ($response->data === null || $response->data === '') {
            throw new RuntimeException("Failed to refresh token: empty response");
        }

        try {
            $data = json_decode($response->data, false, 512, JSON_THROW_ON_ERROR);
        }
        catch (JsonException $e) {
            throw new RuntimeException("Failed to refresh token: invalid JSON response", 0, $e);
        }

        if (
            !is_object($data) ||
            !isset($data->access_token, $data->refresh_token, $data->token_type, $data->expires_in) ||
            !is_string($data->access_token) || $data->access_token === '' ||
            !is_string($data->refresh_token) || $data->refresh_token === '' ||
            !is_string($data->token_type) || $data->token_type === ''
        ) {
            throw new RuntimeException("Failed to refresh token: invalid JSON structure");
        }

        $expiresIn = filter_var($data->expires_in, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1],
        ]);

        if ($expiresIn === false) {
            throw new RuntimeException("Failed to refresh token: expires_in is invalid");
        }

        return new AccessToken(
            $data->access_token,
            $data->refresh_token,
            $data->token_type,
            time() + $expiresIn,
            $token->id_token
        );
    }

    public function getUserInfo (AccessToken $token):AlfaUser {
        $access_token = trim($token->access_token);
        if ($access_token === "") {
            throw new RuntimeException("Failed to get user info: access_token is missing");
        }

        $host = $this->sandbox ? "https://sandbox.alfabank.ru/oidc/userinfo" : "https://baas.alfabank.ru/oidc/userinfo";

        $response = self::sendRequest($host, "GET", $this->security_bundle, null, [
            "Authorization: Bearer $access_token",
            "Accept: application/jwt"
        ]);

        if ($response->error || $response->code !== 200) {
            throw new RuntimeException("Failed to get user info: HTTP {$response->code}" . ($response->error ? " ({$response->error})" : ''), $response->code);
        }

        if ($response->data === null || $response->data === "") {
            throw new RuntimeException("Failed to get user info: empty response");
        }

        try {
            $userData = $this->verifyJwtRs256($response->data);
        }
        catch (Exception $e) {
            throw new RuntimeException("Failed to get user info: " . $e->getMessage(), 0, $e);
        }

        if (
            !is_object($userData) ||
            !isset($userData->given_name, $userData->family_name, $userData->phone_number) ||
            !is_string($userData->given_name) || $userData->given_name === "" ||
            !is_string($userData->family_name) || $userData->family_name === "" ||
            !is_string($userData->phone_number) || $userData->phone_number === ""
        ) {
            throw new RuntimeException("Failed to get user info: invalid JSON structure");
        }

        return new AlfaUser(
            $userData->given_name,
            $userData->family_name,
            $userData->middle_name ?? null,
            $userData->email ?? null,
            $userData->gender ?? null,
            $userData->birthdate ?? null,
            $userData->phone_number,
            $userData->citizenship ?? null,
            $userData->package_name ?? null,
            $userData->package_code ?? null
        );
    }

    private static function sendRequest (
        string $host,
        string $method = "GET",
        ?SecurityBundle $security_bundle = null,
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

        if ($security_bundle) {
            $curl_opt[CURLOPT_SSLCERT]        = $security_bundle->certificate_file_path;
            $curl_opt[CURLOPT_SSLKEY]         = $security_bundle->certificate_secret_file_path;
            $curl_opt[CURLOPT_SSL_VERIFYPEER] = true;
            $curl_opt[CURLOPT_SSL_VERIFYHOST] = 2;

            if ($security_bundle->certificate_chain_file_path) $curl_opt[CURLOPT_CAINFO] = $security_bundle->certificate_chain_file_path;
            if ($security_bundle->certificate_pass) $curl_opt[CURLOPT_KEYPASSWD] = $security_bundle->certificate_pass;
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

    private static function b64url_decode_str(string $value): string {
        $value = strtr($value, '-_', '+/');
        $pad = strlen($value) % 4;
        if ($pad !== 0) {
            $value .= str_repeat('=', 4 - $pad);
        }

        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64url data');
        }

        return $decoded;
    }

    private function verifyJwtRs256(string $jwt): object {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new RuntimeException('Invalid JWT compact serialization');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $headerJson = self::b64url_decode_str($encodedHeader);
        $header = json_decode($headerJson, false, 512, JSON_THROW_ON_ERROR);

        if (!is_object($header) || !isset($header->alg) || !is_string($header->alg)) {
            throw new RuntimeException('JWT header is invalid');
        }

        if ($header->alg !== 'RS256') {
            throw new RuntimeException('Unexpected JWT alg');
        }

        $signature = self::b64url_decode_str($encodedSignature);

        $signingInput = $encodedHeader . '.' . $encodedPayload;

        $ok = openssl_verify(
            $signingInput,
            $signature,
            $this->security_bundle->signature,
            OPENSSL_ALGO_SHA256
        );

        if ($ok !== 1) {
            throw new RuntimeException('JWT signature verification failed');
        }

        $payloadJson = self::b64url_decode_str($encodedPayload);
        $payload = json_decode($payloadJson, false, 512, JSON_THROW_ON_ERROR);

        if (!is_object($payload)) {
            throw new RuntimeException('JWT payload is invalid');
        }

        return $payload;
    }
}