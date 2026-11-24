<?php

declare(strict_types=1);

namespace App\Repositories;

use PDO;

class UserRepository
{
    public function __construct(private PDO $pdo) {}

    public function findByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        return $user ?: null;
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT id, nama, email, role, created_at FROM users WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $id]);
        $user = $stmt->fetch();

        return $user ?: null;
    }

    public function create(string $nama, string $email, string $hashedPassword, string $role): array
    {
        $sql = 'INSERT INTO users (nama, email, password, role)
                VALUES (:nama, :email, :password, :role)
                RETURNING id, nama, email, role, created_at';

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'nama' => $nama,
            'email' => $email,
            'password' => $hashedPassword,
            'role' => $role,
        ]);

        return $stmt->fetch();
    }
}