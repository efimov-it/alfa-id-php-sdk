<?php
declare(strict_types=1);

namespace AlfaID\Domain\DTO;

final class AlfaUser {
    public function __construct(
        public string $name, // given_name
        public string $surname, // family_name
        public ?string $midname, // middle_name
        public string $email, // email
        public string $gender, // gender
        public string $bdate, // birthdate
        public string $phone, // phone_number
        public string $citizenship, // citizenship
        public string $package_name, // package_name
        public string $package_code // package_code
    ) {}
}