<?php
declare(strict_types=1);

namespace AlfaID;

use AlfaID\DTO\AccessToken;
use AlfaID\DTO\AlfaUser;
use AlfaID\DTO\AuthCode;

final class Client {
    private string $client_id;
    private string $client_secret;
    private string $default_redirect_uri;
    private bool $sandbox;

    public function __construct(string $client_id, string $client_secret, string $default_redirect_uri, bool $sandbox = true) {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->default_redirect_uri = $default_redirect_uri;
        $this->sandbox = $sandbox;
    }

    public function getLinkForAuth (string $state, string $scope = "openid", ?string $redirect_uri = null): string {
        $host = $this->sandbox ? "https://id-sandbox.alfabank.ru" : "https://id.alfabank.ru";
        $uri = $redirect_uri ?: $this->default_redirect_uri;
        return $host . "/oidc/authorize?response_type=code&client_id=$this->client_id&redirect_uri=$uri&scope=$scope&state=$state";
    }

    public function processAuthCode ():AuthCode|bool {
        $authCode = $_GET["code"] ?? null;
        $state = $_GET["state"] ?? null;
        if (!$authCode || !$state) return false;

        return new AuthCode($authCode, $state);
    }

    public function getToken (AuthCode $code, ?string $redirect_uri):AccessToken {
        $host = $this->sandbox ? "https://sandbox.alfabank.ru/oidc/token" : "https://baas.alfabank.ru/oidc/token";

        return new AccessToken(
            "access_token",
            "refresh_token",
            "Bearer",
            3600,
            "id_token"
        );
    }

    public function getTokenFromStorage ():AccessToken|null {

        return new AccessToken(
            "access_token",
            "refresh_token",
            "Bearer",
            3600,
            "id_token"
        );
    }

    public function refreshToken (AccessToken $token):AccessToken|bool {
        $host = $this->sandbox ? "https://sandbox.alfabank.ru/oidc/token" : "https://baas.alfabank.ru/oidc/token";

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

        return new AlfaUser(
            "Иван",
            "Иванов",
            null,
            "i.ivanov@example.com",
            "m",
            "2000-01-01",
            "+78005553535",
            "RU",
            "",
            ""
        );
    }
}