<?php
declare(strict_types=1);

namespace AlfaID\Domain\DTO;

final class AccessToken {
    public function __construct(
        public string $access_token,
        public string $refresh_token,
        public string $token_type,
        public int $expires_in,
        public string $id_token
    ) {}
}