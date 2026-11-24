<?php

declare(strict_types=1);

namespace App\Middleware;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Throwable;

class AuthMiddleware
{
    public static function authenticate(): ?array
    {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

        if (!preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
            http_response_code(401);
            echo json_encode([
                'status' => 'error',
                'message' => 'Token autentikasi tidak ditemukan',
            ], JSON_PRETTY_PRINT);
            return null;
        }

        try {
            $jwtSecret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET') ?: '';
            $decoded = JWT::decode($matches[1], new Key($jwtSecret, 'HS256'));

            return [
                'id' => (int) $decoded->sub,
                'email' => (string) $decoded->email,
                'role' => (string) $decoded->role,
            ];
        } catch (Throwable) {
            http_response_code(401);
            echo json_encode([
                'status' => 'error',
                'message' => 'Token tidak valid atau sudah kedaluwarsa',
            ], JSON_PRETTY_PRINT);
            return null;
        }
    }

    public static function authorizeRoles(array $user, array $allowedRoles): bool
    {
        if (!in_array($user['role'], $allowedRoles, true)) {
            http_response_code(403);
            echo json_encode([
                'status' => 'error',
                'message' => 'Akses ditolak. Role Anda tidak memiliki izin untuk aksi ini',
            ], JSON_PRETTY_PRINT);
            return false;
        }

        return true;
    }
}