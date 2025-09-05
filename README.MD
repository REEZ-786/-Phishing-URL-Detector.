  Phishing URL Detector

   Project Title: Phishing URL Detector

    Overview

The  Phishing URL Detector  is a full-stack web application designed to help users identify and avoid malicious links. This project serves as a practical demonstration of core  Security Operations Center (SOC)  functionalities, including threat detection, secure user management, and system monitoring.

The application is built on a robust architecture using  Python Flask  for the backend,  SQLite  for data persistence, and a modern frontend stack of  HTML, CSS, and JavaScript .

    Key Features

   Heuristics-Based Detection Engine:  The core of the application's intelligence is a rule-based engine that analyzes URLs for multiple phishing indicators. It provides a detailed threat assessment with a confidence score and specific reasons for its verdict.
   Role-Based User Management:  The system supports two distinct user roles, `Client` and `Admin`, with separate login pages and dashboards.
   Secure Authentication:  User accounts are protected using secure password hashing (`bcrypt`) and session management via Flask-Login.
   Comprehensive Admin Dashboard:  The admin user has a powerful dashboard with dedicated pages for:
      Managing user accounts (adding and removing users).
      Reviewing and replying to all submitted user feedback.
      Viewing a complete, system-wide log of all URL checks.
   User Feedback System:  Clients can submit feedback on any URL analysis, which is stored in the database for admin review.
   Centralized Logging:  The application uses Python's `logging` module to record all critical events, providing a timestamped audit trail for security monitoring and debugging.

    Project Architecture



The application follows a modular architecture:
   Backend (`app.py`):  The central hub that processes all requests, handles authentication, runs the detection logic, and manages database operations.
   Frontend (`/templates`, `/static`):  The user interface layer, consisting of HTML templates, CSS for styling, and JavaScript for dynamic interactions.
   Database (`site.db`):  An SQLite database that serves as the single source of truth for all project data.

    Technologies Used

   Backend:  Python 3.x, Flask, Flask-SQLAlchemy, Flask-Login, Requests, Werkzeug.
   Database:  SQLite.
   Frontend:  HTML5, CSS3, JavaScript.
   Dependencies:  `python-dotenv`, `werkzeug.security`.

    Getting Started

     Prerequisites

To run this application, you need to have  Python 3.x  installed.

     Installation

1.   Clone the repository: 
    ```bash
    git clone [your-repository-url]
    cd [your-project-directory]
    ```

2.   Install the required Python libraries: 
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-Login Werkzeug requests python-dotenv
    ```

3.   Set up Environment Variables: 
    Create a file named `.env` in your project's root directory and add the following:
    ```
      Securely generated secret key for Flask sessions
    SECRET_KEY="your_very_secure_secret_key_here"

      Your Google Safe Browsing API key (for optional enhanced detection)
    GOOGLE_SAFE_BROWSING_API_KEY="your_google_api_key_here"
    ```
     Note: A strong `SECRET_KEY` can be generated with `python -c 'import secrets; print(secrets.token_hex(16))'` 

     Running the Application

1.   Start the Flask server: 
    ```bash
    python app.py
    ```

2.   Access the application: 
    Open your web browser and go to `http://127.0.0.1:5000/`.

    Default Credentials

The application automatically creates default users on its first run:
   Admin:  `username: admin`, `password: adminpass`
   Client:  `username: client`, `password: clientpass`

    Project Status

This project is a completed proof-of-concept. All core features outlined in the key features section are fully functional.

