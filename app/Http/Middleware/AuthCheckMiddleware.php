<?php

namespace App\Http\Middleware;

use App\Helper\JWTToken;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthCheckMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->cookie('token');
        if (!$token) {
            return $next($request);
        } else {
            $result = JWTToken::verifyToken($token);
            if ($result == 'unauthorized') {
                return $next($request);
            }

            if ($result->role == 'customer') {
                $request->headers->set('role', 'customer');
            } elseif ($result->role == 'admin') {
                $request->headers->set('role', 'admin');
            }
            return $next($request);
        }
    }
}
