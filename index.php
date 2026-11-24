<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/config/database.php';

use App\Controllers\AuthController;
use App\Middleware\AuthMiddleware;
use App\Repositories\UserRepository;
use Dotenv\Dotenv;

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

try {
    $pdo = getDatabaseConnection();
    $userRepository = new UserRepository($pdo);
    $authController = new AuthController($userRepository);

    $method = $_SERVER['REQUEST_METHOD'];
    $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $rawBody = file_get_contents('php://input');
    $input = json_decode($rawBody, true) ?? [];

    if ($uri === '/api/register' && $method === 'POST') {
        $authController->register($input);
        exit;
    }

    if ($uri === '/api/login' && $method === 'POST') {
        $authController->login($input);
        exit;
    }

    // Endpoint terproteksi: cek profil user yang sedang login (ADMIN & USER)
    if ($uri === '/api/me' && $method === 'GET') {
        $authUser = AuthMiddleware::authenticate();
        if ($authUser === null) {
            exit;
        }

        $profile = $userRepository->findById($authUser['id']);
        http_response_code(200);
        echo json_encode([
            'status' => 'success',
            'data' => $profile,
        ], JSON_PRETTY_PRINT);
        exit;
    }

    // Endpoint khusus role ADMIN
    if ($uri === '/api/admin-only' && $method === 'GET') {
        $authUser = AuthMiddleware::authenticate();
        if ($authUser === null || !AuthMiddleware::authorizeRoles($authUser, ['ADMIN'])) {
            exit;
        }

        http_response_code(200);
        echo json_encode([
            'status' => 'success',
            'message' => 'Selamat datang, Admin!',
            'user' => $authUser,
        ], JSON_PRETTY_PRINT);
        exit;
    }

    http_response_code(404);
    echo json_encode([
        'status' => 'error',
        'message' => 'Endpoint tidak ditemukan',
    ], JSON_PRETTY_PRINT);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Internal Server Error: ' . $e->getMessage(),
    ], JSON_PRETTY_PRINT);
}