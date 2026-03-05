<?php
declare(strict_types=1);

namespace AlfaID\Domain\DTO;

final class AuthCode {
    public function __construct(
        public readonly string $state,
        public readonly ?string $code = null,
        public readonly ?string $error = null
    ){}
}