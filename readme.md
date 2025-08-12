# Flask MySQL Web Application

This is a simple web application built with Flask and MySQL that allows users to register, log in, and view their dashboard. It demonstrates the  use of Flask, MySQL integration, and user authentication using Flask-WTF forms.

# Website

You can visit the live application here: httphttp://rishabhkashyap01.pythonanywhere.com/

# Requirements

Before you begin, ensure you have met the following requirements:

1.  Python 3.x
2.  Flask
3.  Flask-WTF
4.  Flask-MySQL
5.  bcrypt
6.  MySQL Server

# Install dependencies:

        pip install -r requirements.txt

This will install all necessary Python libraries including Flask, Flask-WTF, MySQL Connector, and bcrypt.

Environment Setup

# 1. Set up SQL Database:

Use a local database to develop or use a online database to deploy.

# 2. Create a users table:

Create a table to store user data (name, email, password):

    CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
    );

# 3. Database Configuration:

In the app.py file, set the SQL connection parameters such as MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, and MYSQL_DB according to your local or online setup.

    app.config['MYSQL_HOST'] = 'host_name'
    app.config['MYSQL_USER'] = 'user_name'
    app.config['MYSQL_PASSWORD'] = 'your_password_here'
    app.config['MYSQL_DB'] = 'database_name'

# Application Overview

## The Flask MySQL application consists of the following:

**Home Page**: A simple home page that introduces the application

**Registration Page**: Users can register by providing their name, email, and password.

**Login Page**: Registered users can log in with their credentials.

**Dashboard Page**: Displays user information after successful login.

**Logout**: Allows users to log out and clear their session.

# Security:

Passwords are hashed using bcrypt before being stored in the database to ensure secure authentication.
Flask-WTF is used to handle form validation and CSRF protection.

#  Run the Application:

After completing the setup, you can run the Flask application with:

    python app.py

# Access the Application:

Once the application is running, you can access it in your web browser at http://127.0.0.1:5000/.
