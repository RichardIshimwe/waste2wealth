<?php

use App\Http\Controllers\ProductsController;
use App\Http\Controllers\UserAuthenticationController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::prefix('v1')->group(function () {
    Route::post('login', [UserAuthenticationController::class, 'login']);
    Route::post('register', [UserAuthenticationController::class, 'register']);
});

Route::prefix('v1')->middleware('auth:sanctum')->group(function () {
    Route::post('logout', [UserAuthenticationController::class, 'logout']);
    Route::apiResource('products', ProductsController::class);
});

Route::get('products', [ProductsController::class, 'index'])->name('products.index');
Route::get('products/{product}', [ProductsController::class, 'show'])->name('products.show');
Route::post('products', [ProductsController::class, 'store'])->name('products.store');
Route::put('products/{product}', [ProductsController::class, 'update'])->name('products.update');
Route::delete('products/{product}', [ProductsController::class, 'destroy'])->name('products.destroy');

// Route::post('login', [UserAuthenticationController::class, 'login']);
// Route::post('register', [UserAuthenticationController::class, 'register']);
// Route::post('logout', [UserAuthenticationController::class, 'logout'])->middleware('auth:sanctum');