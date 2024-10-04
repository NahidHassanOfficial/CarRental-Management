<?php

namespace App\Helper;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTToken
{
    /**
     * Create a new class instance.
     */
    public function __construct()
    {
        //
    }

    public static function createToken($userEmail, $userID, $time, $role)
    {
        $key = env('JWT_KEY');
        $payload = [
            'iss' => 'NexTrend',
            'iat' => time(),
            'exp' => $time,
            'userEmail' => $userEmail,
            'userID' => $userID,
            'role' => $role,
        ];
        return JWT::encode($payload, $key, 'HS256');
    }

    public static function verifyToken($token)
    {
        try {
            if ($token == null) {
                return 'unauthorized';
            } else {
                $key = env('JWT_KEY');
                return JWT::decode($token, new Key($key, 'HS256'));
            }
        } catch (Exception $e) {
            return 'unauthorized';
        }
    }
}
