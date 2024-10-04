<?php

namespace App\Http\Controllers\Frontend;

use App\Http\Controllers\Controller;
use App\Http\Controllers\InvoiceController;
use App\Models\Car;
use App\Models\Rental;
use Carbon\Carbon;
use Illuminate\Http\Request;

class RentalController extends Controller
{

    public function bookingCancel($id)
    {
        $rental = Rental::where('user_id', request()->header('id'))->find($id);

        if ($rental) {
            if ($rental->start_date > now()->toDateString()) {
                $rental->status = 'Canceled';
                $rental->save();

                noty()->success('Booking cancelled successfully');
                return redirect()->back();

            } else {
                noty()->error('You cannot cancel booking now');
                return redirect()->back();
            }
        } else {
            noty()->error('Booking not found');
            return redirect()->back();
        }
    }

    public function bookingConfirm(Request $request)
    {

        $carId = $request->id;

        $Notavailable = Car::where('id', $carId)->where('availability', 0)->first();

        if ($Notavailable) {
            noty()->error('Car is not available');
            return redirect()->back();
        }

        $pickDate = Carbon::parse($request->pickDate)->toDateString();
        $dropDate = Carbon::parse($request->dropDate)->toDateString();

        $userId = $request->header('id');

        $now = Carbon::now()->toDateString();
        if ($pickDate < $now || $dropDate < $now) {
            noty()->error('Pick date and drop date cannot be past dates');
            return redirect()->back();
        }

        if ($dropDate < $pickDate) {
            noty()->error('Drop date must be the same date as pick date or a future date');
            return redirect()->back();
        }

        $existingRental = Rental::where('car_id', $carId)
            ->where('status', null)
            ->where('start_date', '<=', $dropDate)
            ->where('end_date', '>=', $pickDate)
            ->exists();
        if ($existingRental) {
            noty()->error('Car is already booked for the selected date range');
            return redirect()->back();
        }

        $rental = new Rental();
        $rental->user_id = $userId;
        $rental->car_id = $carId;
        $rental->start_date = $pickDate;
        $rental->end_date = $dropDate;

        $perDayRent = Car::where('id', $carId)->value('daily_rent_price');
        $rental->total_cost = (abs(Carbon::parse($dropDate)->diffInDays(Carbon::parse($pickDate))) + 1) * $perDayRent;

        $rental->save();
        $rentalId = $rental->id;
        noty()->success('Booking confirmed successfully');

        $invoiceController = new InvoiceController();
        return $invoiceController->sendMail($rentalId);
    }
}
