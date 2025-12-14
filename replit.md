# VClub Shop

## Overview

VClub Shop is a full-stack CC marketplace with user authentication, seller functionality, and admin management. Built with React frontend and Express.js backend with PostgreSQL database.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend
- **Framework**: React 18 with Vite
- **Styling**: Custom CSS (mobile-first responsive)
- **Port**: 5000

### Backend
- **Framework**: Express.js
- **Port**: 3001
- **API**: RESTful with `/api` prefix
- **Proxy**: Vite proxies `/api` to backend

### Authentication
- **Method**: JWT tokens in HTTP-only cookies
- **Password**: bcryptjs hashing
- **Roles**: user, seller, admin

### Database (PostgreSQL)
- **users**: id, username, password_hash, role, balance, created_at
- **listings**: id, seller_id, title, card_type, card_brand, country, price, details, status
- **transactions**: id, user_id, listing_id, type, amount, status, tx_hash
- **admin_settings**: wallet_address, qr_code_url, site_name, btc_rate, bonus_percentage

## Features

### User Features
- Register/Login (username & password only)
- Rules popup modal appears on every login (shows refund/payment rules)
- Browse marketplace listings
- Purchase CC items
- View purchased card details (card number, expiry, CVV) in Orders page
- View transaction history
- Deposit funds (BTC) - default landing page after login
- Request refunds on purchases
- View refund request status

### Seller Features
- Create CC listings with full card details (number, expiry, CVV)
- Manage own listings
- Track sales

### Admin Features
- Manage all users (role, balance)
- Update site settings
- Change wallet address & upload QR code image
- View all listings and transactions
- Approve or reject CC listings (pending listings require admin approval before appearing in marketplace)
- Approve or reject refund requests (with automatic balance adjustments)

### Navigation Structure
- News
- CCS/Fullz (submenu: Buy, Cart, Orders, BIN Lookup, BIN Preorder)
- Dumps, Proxy/Socks, Rent SIM, Lottery, SSN/DOB, Accounts
- Billing (submenu: Deposit, Transactions, My Refunds)
- Support, Profile

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection
- `JWT_SECRET` - JWT signing key

## Running the App
- `npm run dev` - Starts both backend and frontend
- Admin login: username `admin`, password `admin123`
