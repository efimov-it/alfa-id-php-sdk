<?php
declare(strict_types=1);

namespace AlfaID\Domain\DTO;

final class ApiResponseWrapper {
    public function __construct(
        public int $code,
        public ?string $data = null,
        public ?string $error = null,
        public int $error_number = 0
    ) {}
}