<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Repositories\UserRepository;
use Firebase\JWT\JWT;

class AuthController
{
    public function __construct(private UserRepository $userRepository) {}

    public function register(array $input): void
    {
        $nama = trim((string) ($input['nama'] ?? ''));
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');
        $role = strtoupper(trim((string) ($input['role'] ?? 'USER')));

        if ($nama === '' || $email === '' || $password === '') {
            $this->jsonResponse(422, [
                'status' => 'error',
                'message' => 'Field nama, email, dan password wajib diisi',
            ]);
            return;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->jsonResponse(422, [
                'status' => 'error',
                'message' => 'Format email tidak valid',
            ]);
            return;
        }

        if (strlen($password) < 6) {
            $this->jsonResponse(422, [
                'status' => 'error',
                'message' => 'Password minimal 6 karakter',
            ]);
            return;
        }

        if (!in_array($role, ['ADMIN', 'USER'], true)) {
            $this->jsonResponse(422, [
                'status' => 'error',
                'message' => 'Role tidak valid. Pilih ADMIN atau USER',
            ]);
            return;
        }

        if ($this->userRepository->findByEmail($email) !== null) {
            $this->jsonResponse(409, [
                'status' => 'error',
                'message' => 'Email sudah terdaftar',
            ]);
            return;
        }

        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $user = $this->userRepository->create($nama, $email, $hashedPassword, $role);

        $this->jsonResponse(201, [
            'status' => 'success',
            'message' => 'Registrasi berhasil',
            'data' => $user,
        ]);
    }

    public function login(array $input): void
    {
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        if ($email === '' || $password === '') {
            $this->jsonResponse(422, [
                'status' => 'error',
                'message' => 'Email dan password wajib diisi',
            ]);
            return;
        }

        $user = $this->userRepository->findByEmail($email);

        if ($user === null || !password_verify($password, $user['password'])) {
            $this->jsonResponse(401, [
                'status' => 'error',
                'message' => 'Email atau password salah',
            ]);
            return;
        }

        $issuedAt = time();
        $expireAt = $issuedAt + (60 * 60 * 24); // Berlaku 24 jam

        $payload = [
            'iat' => $issuedAt,
            'exp' => $expireAt,
            'sub' => $user['id'],
            'email' => $user['email'],
            'role' => $user['role'],
        ];

        $jwtSecret = $_ENV['JWT_SECRET'] ?? getenv('JWT_SECRET') ?: '';
        $token = JWT::encode($payload, $jwtSecret, 'HS256');

        $this->jsonResponse(200, [
            'status' => 'success',
            'message' => 'Login berhasil',
            'token' => $token,
            'user' => [
                'id' => $user['id'],
                'nama' => $user['nama'],
                'email' => $user['email'],
                'role' => $user['role'],
            ],
        ]);
    }

    private function jsonResponse(int $statusCode, array $payload): void
    {
        http_response_code($statusCode);
        echo json_encode($payload, JSON_PRETTY_PRINT);
    }
}