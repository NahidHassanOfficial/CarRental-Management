<?php

use App\Http\Controllers\Admin\CarController as AdminCarController;
use App\Http\Controllers\Admin\CustomerController;
use App\Http\Controllers\Admin\RentalController as AdminRentalController;
use App\Http\Controllers\Frontend\CarController;
use App\Http\Controllers\Frontend\PageController;
use App\Http\Controllers\Frontend\RentalController;
use App\Http\Controllers\UserController;
use App\Http\Middleware\AdminVerificationMiddleware;
use App\Http\Middleware\AuthCheckMiddleware;
use App\Http\Middleware\RedirectIfAuthenticated;
use App\Http\Middleware\TokenVerificationMiddleware;
use Illuminate\Support\Facades\Route;

Route::middleware([AuthCheckMiddleware::class])->group(function () {
    Route::get('/', [PageController::class, 'homePage'])->name(name: 'index');
    Route::get('/cars', [CarController::class, 'carPage']);
    Route::get('/profile/booking/{carID?}', [PageController::class, 'bookingPage'])->name('booking.page');
});

Route::middleware([RedirectIfAuthenticated::class])->group(function () {
    Route::get('/login', [PageController::class, 'loginPage']);
    Route::get('/register', [PageController::class, 'registerPage']);
    Route::post('/login', [UserController::class, 'login']);
    Route::post('/register', [UserController::class, 'register'])->name('user.register');
});

Route::get('/logout', [UserController::class, 'logout']);

Route::middleware([TokenVerificationMiddleware::class])->group(function () {

    Route::get('/profile/history', [PageController::class, 'historyPage'])->name('profile');

    Route::get('/profile/setting', [PageController::class, 'settingPage'])->name('profile.setting');
    Route::post('/profile/setting', [UserController::class, 'updateUserInfo'])->name('update.userInfo');

    Route::get('/profile/booking/confirm/{carID}/{pickDate}/{dropDate}', [PageController::class, 'bookingConfirmPage'])->name('confirm.page');
    Route::post('/profile/booking/confirmed', [RentalController::class, 'bookingConfirm'])->name('booking.confirmed');
    Route::get('/profile/booking/cancel/{id}', [RentalController::class, 'bookingCancel'])->name('booking.cancel');

});

Route::middleware([AdminVerificationMiddleware::class])->group(function () {
    Route::get('/admin/dashboard', [PageController::class, 'adminDashboard'])->name('dashboard');

    Route::get('/admin/cars', [AdminCarController::class, 'manageCars'])->name('dashboard.cars');
    Route::get('/admin/car/create', [AdminCarController::class, 'createCarPage'])->name('car.createPage');
    Route::post('/admin/car/create', [AdminCarController::class, 'createCar'])->name('car.create');
    Route::get('/admin/car/update/{id}', [AdminCarController::class, 'updateCarPage'])->name('car.updatePage');
    Route::post('/admin/car/update/{id}', [AdminCarController::class, 'updateCar'])->name('car.update');
    Route::get('/admin/car/delete/{id}', [AdminCarController::class, 'deleteCar'])->name('car.delete');

    Route::get('/admin/users', [CustomerController::class, 'manageUsers'])->name('dashboard.users');
    Route::get('/admin/users/edit/{id}', [CustomerController::class, 'editUserPage'])->name('user.editPage');
    Route::post('/admin/users/edit/{id}', [CustomerController::class, 'editUser'])->name('user.update');
    Route::get('/admin/users/delete/{id}', [CustomerController::class, 'deleteUser'])->name('user.delete');

    Route::get('/admin/rentals', [AdminRentalController::class, 'manageRentals'])->name('dashboard.rentals');
    Route::get('/admin/rentals/edit/{id}', [AdminRentalController::class, 'updateRentalPage'])->name('rental.updatePage');
    Route::post('/admin/rentals/edit/{id}', [AdminRentalController::class, 'updateRental'])->name('rental.update');
    Route::get('/admin/rentals/delete/{id}', [AdminRentalController::class, 'deleteRental'])->name('rental.delete');

});
