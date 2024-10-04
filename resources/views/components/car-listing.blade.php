<!-- Car categories Start -->
<div class="container-fluid categories py-5">
    <div class="container py-5">
        <div class="text-center mx-auto pb-5 wow fadeInUp" data-wow-delay="0.1s" style="max-width: 800px;">
            <h1 class="display-5 text-capitalize mb-3">Vehicle <span class="text-primary">Categories</span></h1>
            <p class="mb-0">Discover a variety of vehicle categories to choose from, with competitive daily rental
                rates and availability.</p>
        </div>

        <!-- Sort Section -->
        <div class="d-flex justify-content-around">
            <div class=" mb-4">
                <form class="d-flex">
                    <div class="row">
                        <div class="mb-2">
                            <select class="form-control" id="sort-by">
                                <option value="model">Model</option>
                                <option value="year">Year</option>
                                <option value="price">Price</option> <!-- Added price sorting -->
                            </select>
                        </div>
                        <div class="mb-2">
                            <select class="form-control" id="order-by">
                                <option value="asc">Ascending</option>
                                <option value="desc">Descending</option>
                            </select>
                        </div>
                        <div class="">
                            <button type="button" class="btn btn-primary" id="sort-button">Sort</button>
                        </div>
                    </div>
                </form>
            </div>

            <!-- Filter Section -->
            <div class=" mb-4">
                <div class="col-md-12">
                    <form class="d-flex">
                        <div class="row">
                            <!-- Availability Filter -->
                            <div class="col">
                                <select class="form-control" id="filter-availability">
                                    <option value="all">All</option>
                                    <option value="yes">Available</option>
                                    <option value="no">Not Available</option>
                                </select>
                            </div>
                            <!-- Year Filter Dropdown -->
                            <div class="col">
                                <select class="form-control" id="filter-year">
                                    <option value="all">All Years</option>
                                    <!-- Dynamic Year Options -->
                                </select>
                            </div>
                            <!-- Model Filter Dropdown -->
                            <div class="col">
                                <select class="form-control" id="filter-model">
                                    <option value="all">All Models</option>
                                    <!-- Dynamic Model Options -->
                                </select>
                            </div>
                            <!-- Car Type Filter Dropdown -->
                            <div class="col">
                                <select class="form-control" id="filter-car-type">
                                    <option value="all">All Types</option>
                                    <option value="Coupe">Coupe</option>
                                    <option value="Sedan">Sedan</option>
                                    <option value="Truck">Truck</option>
                                    <!-- Add more types as needed -->
                                </select>
                            </div>
                            <div class="col">
                                <button type="button" class="btn btn-secondary" id="filter-button">Filter</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <div class="row categories-grid wow fadeInUp" data-wow-delay="0.1s" id="categories-grid">
            @foreach ($cars as $car)
                <div class="col-md-4 col-lg-3 col-sm-6 mb-4" data-model="{{ $car->model }}"
                    data-year="{{ $car->year }}" data-car-type="{{ $car->car_type }}"
                    data-price="{{ $car->daily_rent_price }}"
                    data-availability="{{ $car->availability ? 'yes' : 'no' }}">
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
                                    ${{ $car->daily_rent_price }}/Day</h4> <!-- Added price field -->
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
                </div>
            @endforeach
        </div>
    </div>
</div>
<!-- Car categories End -->

<script>
    $(document).ready(function() {
        // Dynamically populate the year and model dropdowns
        var categories = $('#categories-grid').children();
        var years = new Set();
        var models = new Set();

        categories.each(function() {
            years.add($(this).data('year'));
            models.add($(this).data('model'));
        });

        years = Array.from(years).sort(); // Sort years in ascending order
        models = Array.from(models).sort(); // Sort models alphabetically

        // Populate year dropdown
        years.forEach(function(year) {
            $('#filter-year').append(`<option value="${year}">${year}</option>`);
        });

        // Populate model dropdown
        models.forEach(function(model) {
            $('#filter-model').append(`<option value="${model}">${model}</option>`);
        });

        // Sort functionality
        $('#sort-button').on('click', function() {
            var sortBy = $('#sort-by').val();
            var orderBy = $('#order-by').val();
            var categories = $('#categories-grid').children();

            categories.sort(function(a, b) {
                var aValue = $(a).data(sortBy);
                var bValue = $(b).data(sortBy);

                // Ensure price is treated as a number
                if (sortBy === 'price') {
                    aValue = parseFloat(aValue);
                    bValue = parseFloat(bValue);
                }

                if (typeof aValue === 'string') {
                    if (orderBy === 'asc') {
                        return aValue.localeCompare(bValue);
                    } else {
                        return bValue.localeCompare(aValue);
                    }
                } else if (typeof aValue === 'number') {
                    if (orderBy === 'asc') {
                        return aValue - bValue;
                    } else {
                        return bValue - aValue;
                    }
                }
            });

            $('#categories-grid').html(categories);
        });

        // Filter functionality
        $('#filter-button').on('click', function() {
            var availability = $('#filter-availability').val();
            var filterYear = $('#filter-year').val();
            var filterModel = $('#filter-model').val();
            var filterCarType = $('#filter-car-type').val();
            var categories = $('#categories-grid').children();

            categories.each(function() {
                var isAvailable = $(this).data('availability');
                var carYear = $(this).data('year').toString();
                var carModel = $(this).data('model').toString();
                var carType = $(this).data('car-type');

                var show = true;

                // Filter by availability
                if (availability !== 'all' && isAvailable !== availability) {
                    show = false;
                }

                // Filter by year
                if (filterYear !== 'all' && carYear !== filterYear) {
                    show = false;
                }

                // Filter by model
                if (filterModel !== 'all' && carModel !== filterModel) {
                    show = false;
                }

                // Filter by car type
                if (filterCarType !== 'all' && carType !== filterCarType) {
                    show = false;
                }

                if (show) {
                    $(this).show();
                } else {
                    $(this).hide();
                }
            });
        });
    });
</script>
