# WireGuard VPN Dashboard

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-Web_App-black)
![WireGuard](https://img.shields.io/badge/VPN-WireGuard-green)
![Nginx](https://img.shields.io/badge/Server-Nginx-orange)
![Status](https://img.shields.io/badge/Status-Live-success)

---

## Overview

This project is a web based VPN provisioning system built using Flask. It allows an administrator to create, manage, and distribute WireGuard VPN client configurations through a clean and interactive dashboard.

The system automates key generation, IP allocation, configuration creation, and QR code generation, removing the need for manual VPN setup.

---

## Live Demo

Access the dashboard:

https://vpn.syedhashmi.trade

> Login required

---

## Setup

Install dependencies:

pip install -r requirements.txt

## Why This Project Exists

Creating WireGuard clients manually involves:

* Generating keys
* Assigning IP addresses carefully
* Writing configuration files
* Distributing configs securely
* Tracking users manually

This process becomes messy and error prone.

This dashboard solves that by:

* Automating the entire workflow
* Providing a central management interface
* Reducing human error
* Making VPN deployment fast and consistent

---

## Architecture Diagram

```
        ┌──────────────────────────────┐
        │         User Browser         │
        │  (Login / Dashboard UI)     │
        └──────────────┬──────────────┘
                       │ HTTPS
                       ▼
        ┌──────────────────────────────┐
        │           Nginx              │
        │ Reverse Proxy + SSL         │
        └──────────────┬──────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │         Gunicorn             │
        │   Python App Server          │
        └──────────────┬──────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │        Flask App             │
        │        (app.py)              │
        │                              │
        │  - Routes                    │
        │  - Logic                     │
        │  - Validation                │
        └───────┬───────────┬─────────┘
                │           │
                ▼           ▼
     ┌───────────────┐   ┌───────────────┐
     │ WireGuard CLI │   │   File System │
     │   (wg genkey) │   │               │
     └───────────────┘   │ clients/      │
                         │ keys/         │
                         │ qr_codes/     │
                         │ ip_pool.json  │
                         └──────┬────────┘
                                │
                                ▼
                   ┌────────────────────────┐
                   │   Jinja Templates      │
                   │ index.html / login     │
                   └──────────┬─────────────┘
                              ▼
                   ┌────────────────────────┐
                   │  Rendered Web UI       │
                   │ Dashboard + QR + Table │
                   └────────────────────────┘
```

---

## How It Works

### Login Flow

* User enters username, password, and 2FA code
* Flask validates credentials and TOTP
* Session is created

---

### Client Creation Flow

1. User submits client name
2. Flask:

   * Validates input
   * Assigns next available IP
   * Generates keys using WireGuard CLI
   * Builds configuration file
3. System saves:

   * Config file
   * Public key
   * QR code
   * Updates IP pool
4. Dashboard updates instantly

---

### Client Management

* View all clients in table
* Download configuration files
* Delete clients (removes all associated data)
* Real time stats update automatically

---

### QR Code Setup

* Each config is converted into a QR code
* Mobile users scan directly in WireGuard app
* No manual config needed

---

## Key Features

* Web based VPN management dashboard
* Automatic IP allocation
* WireGuard config generation
* QR code for mobile setup
* Client list with delete functionality
* Two factor authentication login
* Live stats dashboard
* Toast notifications and loader animations
* Clean and responsive UI

---

## Screenshots

### Login Page

<img width="550" height="736" alt="Screenshot 2026-04-28 164956" src="https://github.com/user-attachments/assets/f4fbc194-6229-49e3-b89e-056aa9284c2d" />


### Dashboard

<img width="1234" height="973" alt="Screenshot 2026-04-28 165036" src="https://github.com/user-attachments/assets/edd6e56c-6ec1-4225-beac-a8c4384b3a93" />


### QR Code Generation

<img width="711" height="1023" alt="Screenshot 2026-04-28 163213" src="https://github.com/user-attachments/assets/ed99bd4d-655c-4af3-bd9a-a02ad7c78b57" />


---

## Project Structure

```
vpn-dashboard/
│
├── app.py
├── templates/
│   ├── index.html
│   └── login.html
│
├── clients/
├── keys/
├── qr_codes/
│
├── ip_pool.json
├── requirements.txt
└── README.md
```

---

## Tech Stack

* Python (Flask)
* Gunicorn
* Nginx
* WireGuard
* HTML CSS JavaScript
* Ubuntu VPS

---

## Security Features

* Session based authentication
* Two factor authentication (TOTP)
* Input validation
* Controlled file access
* Secure HTTPS deployment

---

## Benefits

### Speed

Create VPN clients in seconds.

### Consistency

No duplicate IPs or broken configs.

### Usability

Simple interface for non technical users.

### Centralization

All clients managed from one place.

### Scalability

Handles multiple clients without complexity.

---

## Limitations

* Uses JSON instead of a database
* Single user authentication
* No real time VPN connection monitoring
* No automatic router integration

---

## Future Improvements

* Move to SQLite or database backend
* Multi user roles
* REST API endpoints
* Integration with network devices
* Usage analytics and monitoring
* Enhanced UI and theming

---

## Why This Project Matters

This project demonstrates practical skills across:

* Networking and VPN concepts
* Backend development with Flask
* Linux server deployment
* Reverse proxy configuration
* Security with authentication and 2FA
* UI and user experience design

It reflects real world scenarios where automation replaces repetitive manual tasks in infrastructure management.

---

## Summary

This system shows how a web application can simplify and automate VPN provisioning.

It combines backend logic, system level operations, and frontend rendering into a single functional solution that is both practical and scalable.
