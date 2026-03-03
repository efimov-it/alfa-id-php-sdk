<?php
declare(strict_types=1);

namespace AlfaID\Support;

use Ramsey\Uuid\Uuid;

final class AuthState {
    public static function generate ():string {
        return Uuid::uuid4()->toString();
    }
}