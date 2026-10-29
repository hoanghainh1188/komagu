<?php

use App\Http\Controllers\AccountController;
use Illuminate\Support\Facades\Route;

Route::post('/register', [AccountController::class, 'register']);
Route::post('/posts', [AccountController::class, 'post']);
Route::post('/teams', [AccountController::class, 'team']);
Route::post('/account/rename', [AccountController::class, 'rename']);
Route::post('/account/profile', [AccountController::class, 'profile']);
