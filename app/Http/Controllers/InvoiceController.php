<?php

namespace App\Http\Controllers;

use App\Mail\CarRentedToAdmin;
use App\Mail\CarRentedToCustomer;
use App\Models\Rental;
use Illuminate\Support\Facades\Mail;

class InvoiceController extends Controller
{
    public function sendMail($rentalId)
    {

        $rental = Rental::with(['car', 'user'])->where('id', $rentalId)->first();

        Mail::to('hasos19585@sgatra.com')->send(new CarRentedToCustomer($rental));
        Mail::to('hasos19585@sgatra.com')->send(new CarRentedToAdmin($rental));

        noty()->success('Invoice Sent To Email');
        if (request()->header('role') == 'admin') {
            return redirect()->route('dashboard.rentals');
        } else {
            return redirect()->route('profile');
        }

    }
}
