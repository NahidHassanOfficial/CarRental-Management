# Car Rental Web Application

> [!NOTE]
> This is a Car Rental Web Application built using Laravel. The application allows users to browse available cars, make bookings, and manage their rentals. The system also includes an admin dashboard for managing cars, rentals, and customer details.

### Admin Dashboard
- **Manage Cars**: Add, edit, and delete car details (name, brand, model, year, type, daily rent price, availability, image).
- **Manage Rentals**: View, create, update, and delete rental information (rental ID, customer details, car details, rental period, total cost, and status).
- **Manage Customers**: View and manage customer information (name, email, phone number, address, rental history).
- **Dashboard Statistics**: 
  - Total number of cars
  - Number of available cars
  - Total rentals
  - Total earnings from rentals

### Frontend (User Interface)
- **Browse Cars**: Users can filter cars by type, brand, and daily rent price.
- **Make Bookings**: Select a car, choose rental start and end dates, and confirm the booking if the car is available.
- **Manage Bookings**: Users can view their booking history and cancel upcoming bookings if the rental has not started yet.
- **Authentication**: Basic user authentication system (signup, login, logout). Middleware is used to protect routes for booking and viewing rental history.

### Email Notifications
- When a car is rented, both the customer and the admin receive emails with rental details.

### Technical Features
- **Role-based Access Control**: Admins can manage cars, rentals, and customers, while customers can only view and manage their own bookings.