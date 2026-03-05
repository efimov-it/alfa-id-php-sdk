<?php
declare(strict_types=1);

namespace AlfaID;

use AlfaID\Domain\DTO\AccessToken;
use AlfaID\Domain\DTO\AlfaUser;
use AlfaID\Domain\DTO\ApiResponseWrapper;
use AlfaID\Domain\DTO\AuthCode;
use AlfaID\Infrastructure\Http\Tls\CertificateBundle;

use Exception;

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

            var_dump($this->client_secret);
        }
    }

    public function getLinkForAuth (string $state, string $scope = "openid", ?string $redirect_uri = null, bool $reset_consent = false): string {
        $host = $this->sandbox ?
                    "https://id-sandbox.alfabank.ru" :
                    "https://id.alfabank.ru";

        $uri = $redirect_uri ?: $this->default_redirect_uri;

        $consent = $reset_consent ? "&prompt=consent" : "";

        return $host . "/oidc/authorize?response_type=code&client_id=$this->client_id&redirect_uri=$uri&scope=$scope&state=$state" . $consent;
    }

    private static function getSecret (string $client_id, CertificateBundle $cert, bool $sandbox):?string {
        $host = $sandbox ?
                    "https://sandbox.alfabank.ru/oidc/clients/$client_id/client-secret" :
                    "https://baas.alfabank.ru/oidc/clients/$client_id/client-secret";

        $req = self::sendRequest($host, "POST", $cert, null, ['accept: application/json']);

        if ($req->error || $req->code !== 200 || !$req->data) return null;

        $data = json_decode($req->data);

        if (isset($data->clientSecret)) return $data->clientSecret;

        return null;
    }

    public function processAuthCode ():?AuthCode {
        $code  = filter_input(INPUT_GET, 'code',  FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);
        $error = filter_input(INPUT_GET, 'error', FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);
        $state = filter_input(INPUT_GET, 'state', FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);

        $code  = is_string($code)  ? trim($code)  : null;
        $error = is_string($error) ? trim($error) : null;
        $state = is_string($state) ? trim($state) : null;

        if ($code !== null  && strlen($code)  > 2048) return null;
        if ($error !== null && strlen($error) > 256)  return null;
        if ($state === null || strlen($state) > 256)  return null;

        if (!preg_match('/^[A-Za-z0-9\-_]{1,40}$/', $state)) return null;

        if ($code !== null && !preg_match('/^[A-Za-z0-9\-_]{1,40}$/', $code)) return null;

        if ($error !== null && !preg_match('/^[A-Za-z0-9_\-\.]{1,256}$/', $error)) return null;

        if ($code === null && $error === null) return null;

        return new AuthCode($state, $code, $error);
    }

    public function getToken (AuthCode $code, ?string $redirect_uri = null):?AccessToken {
        $host = $this->sandbox ?
                    "https://sandbox.alfabank.ru/oidc/token" :
                    "https://baas.alfabank.ru/oidc/token";

        $uri = $redirect_uri ?? $this->default_redirect_uri;

        $body = "grant_type=authorization_code".
               "&code=$code->code".
               "&client_id=$this->client_id".
               "&client_secret=$this->client_secret".
               "&redirect_uri=$uri";

        $req = self::sendRequest($host, "POST", $this->certificate, $body, [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ]);

        if ($req->error || $req->code !== 200 || !$req->data) return null;

        try {
            $res = json_decode($req->data);

            if (
                $res->access_token &&
                $res->refresh_token &&
                $res->token_type &&
                $res->expires_in &&
                $res->id_token
            ) {
                return new AccessToken(
                    $res->access_token,
                    $res->refresh_token,
                    $res->token_type,
                    time() + $res->expires_in,
                    $res->id_token
                );
            }
        }
        catch (Exception $e) {
            return null;
        }

        return null;
    }

    public function refreshToken (AccessToken $token):AccessToken|bool {
        $host = $this->sandbox ?
                    "https://sandbox.alfabank.ru/oidc/token" :
                    "https://baas.alfabank.ru/oidc/token";

        return false;

        return new AccessToken(
            "access_token",
            "refresh_token",
            "Bearer",
            3600,
            "id_token"
        );
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
            
            $userData = json_decode($decodedData);

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
        ?array $headers = null
    ):ApiResponseWrapper {
        $ch = curl_init($host);

        $method_normalized = strtoupper($method);

        $curl_opt = [
            CURLOPT_RETURNTRANSFER => true,
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

        return new ApiResponseWrapper($code, $res ?? null, ($err !== '') ? $err : null, $errno);
    }
}