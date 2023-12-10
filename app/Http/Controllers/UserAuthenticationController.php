<?php

namespace App\Http\Controllers;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use App\Models\User;

class UserAuthenticationController extends Controller
{
    //
    public function allUsers()
    {
        // return Products::all();
        $users = User::all();

        return response()->json([
            'all_users' => $users,
        ], 200);
    }

    public function updateAmount(Request $request)
{
    $request->validate([
        'amount' => 'required|numeric',
    ]);
    $email = $request->input('email');

    // Find the user by ID
    $user = User::where('email', $request['email'])->firstOrFail();

    // Check if the user exists
    if (!$user) {
        return response()->json(['error' => 'User not found', 'email' => $email ], 404);
    }

    // Update the amount
    $user->amount = $request->input('amount');

    // Save the changes
    $user->save();

    return response()->json(['message' => 'User amount updated successfully'], 200);
}


    public function register(Request $request)
{
        $name = $request->input('name');
        $email = strtolower($request->input('email'));
        $password = $request->input('password');
        $phone = $request->input('phone');

        $user = User::create([
            'name' => $name,
            'phone' => $phone,
            'email' => $email,
            'password' => Hash::make($password)
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => 'User Account Created Successfully',
            'access_token' => $token,
            'token_type' => 'Bearer',
        ], 201);
}
public function login(Request $request)
    {
        $email = strtolower($request->input('email'));
        $password = $request->input('password');

        $credentials = [
            'email' => $email,
            'password' => $password
        ];
        if (!Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Invalid login credentials'
            ], 401);
        }

        $user = User::where('email', $request['email'])->firstOrFail();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ],200);
    }
    public function logout()
{
    auth()->user()->tokens()->delete();

    return response()->json([
        'message' => 'Succesfully Logged out'
    ], 200);
}
}
