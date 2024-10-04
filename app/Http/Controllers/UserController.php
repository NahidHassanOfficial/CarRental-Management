<?php

namespace App\Http\Controllers;

use App\Helper\JWTToken;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{

    public function updateUserInfo(Request $request)
    {
        $validatedRequest = $request->validate([
            'email' => 'sometimes|email',
            'name' => 'sometimes|max:20',
            'password' => 'sometimes|nullable',
        ]);

        $user = User::find($request->header('id'));

        if ($user) {
            foreach ($validatedRequest as $key => $value) {
                if ($key === 'password' && is_null($value)) {
                    continue;
                }

                if ($user->$key !== $value) {
                    $user->$key = $value;
                }
            }

            if ($user->isDirty()) {
                $user->save();
                noty()->success('Updated successfully');
            } else {
                noty()->error('No changes made');
            }
        } else {
            noty()->error('User not found');
        }

        return redirect()->back();
    }

    public function logout()
    {
        return redirect()->to('/')->cookie('token', -1);
    }
    public function login(Request $request)
    {
        $validatedRequest = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $validatedRequest['email'])
            ->where('password', $validatedRequest['password'])
            ->select('id', 'role')->first();

        if ($user->id != null) {
            $time = time() + 60 * 60 * 24 * 7;
            $token = JWTToken::createToken($request->input('email'), $user->id, $time, $user->role);
            $intendedUrl = $request->input('intended_url');
            if ($intendedUrl == null) {
                $intendedUrl = route('profile');
            }
            noty()->success('Login Successfull');
            return redirect()->intended($intendedUrl ?? route('home'))->cookie('token', $token, 60 * 24 * 7);

        } else {
            noty()->error('Login Failed');
            return redirect()->back();
        }
    }

    public function register(Request $request)
    {
        $validatedRequest = $request->validate([
            'email' => 'required|email|unique:users,email',
            'name' => 'required|min:4',
            'password' => 'required',
        ]);

        User::create([
            'name' => $validatedRequest['name'],
            'email' => $validatedRequest['email'],
            'password' => $validatedRequest['password'],
        ]);
        noty()->success('User Registration Successfull');
        return redirect()->to('/login');

    }

}
