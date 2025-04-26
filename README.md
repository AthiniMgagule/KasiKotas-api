# Kasi Kotas API

## Overview

This API serves as the backend for the Kasi Kotas application, a platform that connects township/kasi food shops (specifically kota sandwich shops) with customers. The API handles user authentication, shop registration, menu management, order processing, and notifications.

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
  - [Authentication](#authentication)
  - [User Management](#user-management)
  - [Shop Management](#shop-management)
  - [Kota Management](#kota-management)
  - [Order Management](#order-management)
  - [Notifications](#notifications)
- [Database Schema](#database-schema)
- [Error Handling](#error-handling)
- [Security Features](#security-features)

## Getting Started

### Prerequisites

- Node.js (v14 or later)
- npm (v6 or later)
- SQLite3

### Installation

1. Clone the repository:
   ```
   git clone <https://github.com/AthiniMgagule/KasiKotas-api.git>
   cd kasi-kotas-api
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Set up environment variables (see below)

4. Start the server:
   ```
   npm start
   ```

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```
PORT=2025
JWT_SECRET=your_jwt_secret_key
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_app_password
```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/signup` | Register a new user |
| GET | `/verify-email` | Verify user email address |
| POST | `/login` | User login |
| POST | `/resetPassword` | Request password reset |
| POST | `/confirmReset` | Confirm password reset with token |

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | Get all users |
| GET | `/users/:email` | Get user by email |
| PUT | `/updateUsers/:id` | Update user information |
| PUT | `/updateProfile/:id` | Update user profile |

### Shop Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/registerShop` | Register a new shop |
| GET | `/shops` | Get all shops |
| GET | `/shops/:ownerId` | Get shop by owner ID |
| PUT | `/shops/:shopId` | Update shop information |
| PUT | `/approveShop/:shopId` | Approve or reject shop registration |

### Kota Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/createKota` | Create a new kota menu item |
| GET | `/kotaContents` | Get all kotas |
| GET | `/kotaContents/:ownerId` | Get kotas by owner ID |
| PUT | `/updateKota/:kotaId` | Update kota information |
| DELETE | `/deleteKota/:kotaId` | Delete a kota |

### Order Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/createOrder` | Create a new order |
| GET | `/ownerOrders/:ownerId` | Get all orders for an owner |
| GET | `/orders/:orderId` | Get order by ID |
| PUT | `/updateOrderStatus/:orderId` | Update order status |

### Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/notifications` | Create a notification |
| GET | `/ownerNotifications/:ownerId` | Get notifications for an owner |
| PUT | `/markNotificationRead/:notificationId` | Mark notification as read |
| DELETE | `/deleteNotification/:notificationId` | Delete a notification |

## Database Schema

The API uses SQLite with the following main tables:

- `users`: Stores user information and credentials
- `shops`: Stores shop information
- `kotaContents`: Stores kota menu items and ingredients
- `orders`: Tracks customer orders
- `notifications`: Manages system notifications

## Error Handling

The API implements error handling for common scenarios:
- Input validation errors (400)
- Authentication failures (401)
- Authorization issues (403)
- Resource not found (404)
- Server errors (500)

## Security Features

- Password hashing with bcrypt
- JWT authentication for protected routes
- Email verification for new accounts
- Password reset functionality
- File upload validation and restrictions
- Secure password requirements

## File Upload

The API supports logo uploads for shops:
- Maximum file size: 5MB
- Supported types: Images only
- Files are stored in the `public/uploads/shops` directory
