<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Car Rental Invoice</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            /* Light gray background */
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }

        .card {
            background-color: #ffffff;
            border: 1px solid #dee2e6;
            /* Light gray border */
            border-radius: 5px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .card-body {
            padding: 20px;
        }

        .card-title {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
            /* Bootstrap blue */
            margin-bottom: 20px;
        }

        .card-text {
            font-size: 16px;
            color: #6c757d;
            /* Muted gray */
            margin-bottom: 20px;
        }

        .table {
            width: 100%;
            margin-bottom: 1rem;
            color: #212529;
            border-collapse: collapse;
        }

        .table th,
        .table td {
            padding: 12px;
            text-align: left;
            border: 1px solid #dee2e6;
        }

        .table th {
            background-color: #007bff;
            color: white;
        }

        .table td {
            background-color: #f8f9fa;
        }

        .text-right {
            text-align: right;
        }

        .btn-primary {
            background-color: #007bff;
            border-color: #007bff;
            color: #fff;
            padding: 10px 20px;
            text-align: center;
            display: inline-block;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 20px;
        }

        .btn-primary:hover {
            background-color: #0056b3;
        }

        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 14px;
            color: #6c757d;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <h2 class="card-title">Invoice for Car Rental</h2>
                <p class="card-text">Dear {{ $rental->user->name }}, thank you for renting a car with us! Here are
                    your booking
                    details:</p>

                <table class="table table-bordered">
                    <tr>
                        <th>Item</th>
                        <th>Description</th>
                        <th>Duration</th>
                        <th>Unit Price</th>
                        <th>Total</th>
                    </tr>
                    <tr>
                        <td>Car Rental</td>
                        <td>{{ $rental->car->name }} ({{ $rental->car->car_type }})</td>
                        <td>{{ $rental->start_date }} - {{ $rental->end_date }}</td>
                        <td>${{ $rental->car->daily_rent_price }}/day</td>
                        <td>${{ $rental->total_cost }}</td>
                    </tr>
                    <tr>
                        <td colspan="4" class="text-right">Tax (0%):</td>
                        <td>$0.00</td>
                    </tr>
                    <tr>
                        <td colspan="4" class="text-right">Total:</td>
                        <td>${{ $rental->total_cost }}</td>
                    </tr>
                </table>


            </div>
        </div>

        <div class="footer">
            <p>If you have any questions, feel free to contact us at <a
                    href="mailto:support@example.com">support@example.com</a>.</p>
        </div>
    </div>
</body>

</html>
