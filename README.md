# SecureShare_

SecureShare_ is a secure file sharing web application built with Flask and MySQL. It features end-to-end encryption, digital signatures, and user authentication to ensure secure file transfers between users.

## Features

- 🔐 End-to-end file encryption using AES
- ✍️ Digital signatures using DSA
- 👥 User authentication and authorization
- 🔍 Searchable encryption for admins
- 📊 Admin dashboard with system analytics
- 📥 File upload and download functionality
- 🔄 Real-time file verification

## Prerequisites

Before you begin, ensure you have the following installed:
- Python 3.8 or higher
- XAMPP (for MySQL database)
- Git

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/SecureShare_.git
   cd SecureShare_
   ```

2. **Set Up Python Virtual Environment**
   ```bash
   # Create virtual environment
   python -m venv venv

   # Activate virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up XAMPP**
   - Download and install XAMPP from [https://www.apachefriends.org/](https://www.apachefriends.org/)
   - Start XAMPP Control Panel
   - Start Apache and MySQL services
   - Verify MySQL is running on port 3306

5. **Initialize Database**
   ```bash
   python dbconnect.py
   ```

6. **Generate Security Keys**
   ```bash
   python signatures.py
   python generate_aes_key.py
   ```

7. **Run the Application**
   ```bash
   python app.py
   ```

8. **Access the Application**
   - Open your web browser and go to `http://localhost:5000`
   - Create a new account or log in

## Database Configuration

The default database configuration is:
- Host: 127.0.0.1
- User: root
- Password: (empty)
- Database: is_project
- Port: 3306

If you need to modify these settings, update them in `dbconnect.py` and `app.py`.

## Troubleshooting

1. **MySQL Connection Issues**
   - Ensure XAMPP is running
   - Check if MySQL service is active
   - Verify port 3306 is not in use
   - Check database credentials

2. **File Upload Issues**
   - Check file size limits
   - Ensure uploads directory exists
   - Verify file permissions

3. **Key Generation Issues**
   - Run signatures.py and generate_aes_key.py again
   - Check file permissions
   - Ensure Python has write access

## Security Notes

1. Never share or commit the following files:
   - aes_key.bin
   - dsa_private_key.pem
   - dsa_public_key.pem

2. Keep your MySQL root password secure

3. In production:
   - Change default database credentials
   - Use environment variables for sensitive data
   - Enable HTTPS
   - Set up proper file permissions

## Directory Structure

```
SecureShare_/
├── app.py
├── dbconnect.py
├── generate_aes_key.py
├── signatures.py
├── requirements.txt
├── README.md
├── static/
│   └── input_styles.css
└── templates/
    ├── admin.html
    ├── base.html
    ├── login.html
    ├── signup.html
    └── user.html 
```

## Creating Admin User

To create an admin user, you'll need to directly insert it into the database using MySQL:

1. Open XAMPP Control Panel and start MySQL
2. Open MySQL Console or phpMyAdmin (http://localhost/phpmyadmin)
3. Select the 'is_project' database
4. Run the following SQL query:

```sql
INSERT INTO Users (username, password, role) 
VALUES ('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewIxhCv.xINbW4LS', 'admin');
```

This will create an admin user with:
- Username: admin
- Password: admin123
- Role: admin

You can change the password after logging in. For security, create a new admin account and delete this default one.

Alternative method using Python console:
```python
import bcrypt
import mysql.connector

# Database connection
db_config = {
    'host': "127.0.0.1",
    'user': "root",
    'password': "",
    'database': "is_project",
    'port': 3306
}

# Create admin user
username = "admin"
password = "admin123"
role = "admin"

# Hash the password
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Connect and insert
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()
cursor.execute(
    "INSERT INTO Users (username, password, role) VALUES (%s, %s, %s)",
    (username, hashed_password, role)
)
conn.commit()
cursor.close()
conn.close()