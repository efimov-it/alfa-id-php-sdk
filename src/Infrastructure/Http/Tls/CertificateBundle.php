<?php
declare(strict_types=1);

namespace AlfaID\Infrastructure\Http\Tls;

final class CertificateBundle {
    public readonly string $file_path;
    public readonly string $secret_file_path;
    public readonly ?string $pass;
    public readonly ?string $chain_file_path;

    private function __construct(
        string $file_path,
        string $secret_file_path,
        ?string $chain_file_path = null,
        ?string $pass = null
    ) {
        $this->file_path = $file_path;
        $this->secret_file_path = $secret_file_path;
        $this->chain_file_path = $chain_file_path;
        $this->pass = $pass;
    }

    public static function load (string $file_path, string $secret_file_path, ?string $chain_file_path = null, ?string $pass = null):?self {
        if (
            is_file($file_path) && is_readable($file_path) &&
            is_file($secret_file_path) && is_readable($secret_file_path) &&
            (!$chain_file_path || (is_file($chain_file_path) && is_readable($chain_file_path)))
        ) {
            return new self($file_path, $secret_file_path, $chain_file_path, $pass);
        }

        return null;
    }
}