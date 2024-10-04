<?php

namespace App\Http\Middleware;

use App\Helper\JWTToken;
use App\Helper\Response;
use App\Models\User;
use Closure;
use Illuminate\Http\Request;

class TokenVerificationMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next)
    {
        $token = $request->cookie('token');
        $result = JWTToken::verifyToken($token);
        if ($result == "unauthorized") {
            return redirect('/login')->with('intended_url', $request->url());
        } else {
            $isCustomer = User::where('id', $result->userID)->where('role', 'customer')->exists();
            if ($isCustomer) {
                $request->headers->set('email', $result->userEmail);
                $request->headers->set('id', $result->userID);
                $request->headers->set('role', 'customer');
                return $next($request);
            } else {
                return redirect('/login')->with('intended_url', $request->url());
            }

        }
    }
}
