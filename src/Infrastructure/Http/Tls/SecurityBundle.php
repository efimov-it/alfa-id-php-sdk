<?php
declare(strict_types=1);

namespace AlfaID\Infrastructure\Http\Tls;

use RuntimeException;

final class SecurityBundle {

    private function __construct(
        public readonly string $certificate_file_path,
        public readonly string $certificate_secret_file_path,
        public readonly string $certificate_chain_file_path,
        public readonly string $certificate_pass,
        public readonly string $signature
    ) {}

    public static function load (
        string $certificate_file_path,
        string $certificate_secret_file_path,
        string $certificate_chain_file_path,
        string $certificate_pass,
        string $signature_file_path
    ):?self {
        if (
            is_file($certificate_file_path) && is_readable($certificate_file_path) &&
            is_file($certificate_secret_file_path) && is_readable($certificate_secret_file_path) &&
            is_file($certificate_chain_file_path) && is_readable($certificate_chain_file_path) &&
            is_file($signature_file_path) && is_readable($signature_file_path)
        ) {
            $signature_content = file_get_contents($signature_file_path);

            if ($signature_content === false || trim($signature_content) === '') {
                throw new RuntimeException('Missing OP public key PEM');
            }
            return new self($certificate_file_path, $certificate_secret_file_path, $certificate_chain_file_path, $certificate_pass, $signature_content);
        }

        return null;
    }
}