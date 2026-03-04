<?php
declare(strict_types=1);

namespace AlfaID\Infrastructure\Http\Tls;

final class CertificateBundle {
    public readonly string $cert_file_path;
    public readonly string $cert_secret_file_path;
    public readonly string $cert_chain_file_path;

    private function __construct(
        string $cert_file_path,
        string $cert_secret_file_path,
        string $cert_chain_file_path
    ) {
        $this->cert_file_path = $cert_file_path;
        $this->cert_secret_file_path = $cert_secret_file_path;
        $this->cert_chain_file_path = $cert_chain_file_path;
    }

    public static function load (string $cert_file_path, string $cert_secret_file_path, string $cert_chain_file_path):?self {
        if (
            is_file($cert_file_path) && is_readable($cert_file_path) &&
            is_file($cert_secret_file_path) && is_readable($cert_secret_file_path) &&
            is_file($cert_chain_file_path) && is_readable($cert_chain_file_path)
        ) {
            return new self($cert_file_path, $cert_secret_file_path, $cert_chain_file_path);
        }

        return null;
    }
}