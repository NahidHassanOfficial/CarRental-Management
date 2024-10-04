<!-- Car categories Start -->
<div class="container-fluid categories py-5">
    <div class="container py-5">
        <div class="text-center mx-auto pb-5 wow fadeInUp" data-wow-delay="0.1s" style="max-width: 800px;">
            <h1 class="display-5 text-capitalize mb-3">Vehicle <span class="text-primary">Categories</span></h1>
            <p class="mb-0">Discover a variety of vehicle categories to choose from, with competitive daily rental
                rates and availability.</p>
        </div>
        <div class="categories-carousel owl-carousel wow fadeInUp" data-wow-delay="0.1s">
            @foreach ($cars as $car)
                <div class="categories-item p-4">
                    <div class="categories-item-inner">
                        <div class="categories-img rounded-top">
                            <img src="{{ asset($car->image) }}" class="img-fluid w-100 rounded-top"
                                style="height: 200px; width:200px" alt="Car Image">
                        </div>
                        <div class="categories-content rounded-bottom p-4">
                            <h4>{{ $car->brand }}</h4>
                            <p>Model: {{ $car->model }}</p>
                            <p>Year: {{ $car->year }}</p>
                            <p>Car Type: {{ $car->car_type }}</p>
                            <h4 class="bg-white text-primary rounded-pill py-2 px-4 mb-0">
                                ${{ $car->daily_rent_price }}/Day</h4>
                            <p>Available: {{ $car->availability ? 'Yes' : 'No' }}</p>
                            @if ($car->availability)
                                <a href="{{ route('booking.page', $car->id) }}"
                                    class="btn btn-primary rounded-pill d-flex justify-content-center py-3">Book
                                    Now</a>
                            @else
                                <a class="btn btn-dark rounded-pill d-flex justify-content-center py-3">Not
                                    Available now</a>
                            @endif

                        </div>
                    </div>
                </div>
            @endforeach
        </div>
    </div>
</div>
<!-- Car categories End -->
