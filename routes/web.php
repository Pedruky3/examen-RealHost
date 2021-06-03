<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PrototypeController;
/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/inicio', [PrototypeController::class, 'index'])->name('inicio');
Route::post('/encrypt', [PrototypeController::class, 'encrypt'])->name('encrypt');
Route::post('/generateKey', [PrototypeController::class, 'generateKey'])->name('generateKey');
Route::post('/decrypt', [PrototypeController::class, 'decrypt'])->name('decrypt');

