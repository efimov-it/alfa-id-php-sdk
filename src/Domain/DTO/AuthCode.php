<?php
declare(strict_types=1);

namespace AlfaID\Domain\DTO;

final class AuthCode {
    public function __construct(
        public string $code,
        public string $state
    ){}
}