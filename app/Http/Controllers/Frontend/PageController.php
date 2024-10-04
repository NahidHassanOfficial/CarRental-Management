<?php

namespace App\Http\Controllers\Frontend;

use App\Http\Controllers\Controller;
use App\Models\Car;
use App\Models\Rental;
use App\Models\User;
use DateTime;

class PageController extends Controller
{

    public function adminDashboard()
    {
        $carCount = Car::count();
        $availableCarCount = Car::where('availability', '1')->count();
        $rentalCount = Rental::count();

        $totalEarning = Rental::where('status', null)->sum('total_cost');

        return view('components.admin-dash.dashboard', compact('carCount', 'availableCarCount', 'rentalCount', 'totalEarning'));

    }

    public function loginPage()
    {
        return view('components.login');

    }
    public function registerPage()
    {
        return view('components.register');

    }

    public function bookingPage()
    {
        $cars = Car::select('id', 'name')->get();
        return view('components.layouts.booking-page', compact('cars'));
    }
    public function bookingConfirmPage($carID, $pickDate, $dropDate)
    {
        $car = Car::where('id', $carID)->first();

        $startDate = new DateTime($pickDate);
        $endDate = new DateTime($dropDate);
        $days = $startDate->diff($endDate)->days + 1;
        $totalCost = $days * $car->daily_rent_price;

        return view('components.layouts.confirm-page', compact('car', 'pickDate', 'dropDate', 'totalCost'));
    }
    public function homePage()
    {
        $cars = \App\Models\Car::all();
        return view('components.index', compact('cars'));
    }

    public function historyPage()
    {
        $bookings = Rental::where('user_id', request()->header('id'))->with('car')->get();
        return view('components.user-profile.profile', compact('bookings'));
    }public function settingPage()
    {
        $user = User::where('id', request()->header('id'))->first();
        return view('components.user-profile.setting', compact('user'));
    }
}
