#  Authentication System

This project is a secure, full-featured authentication system built with **Node.js**, **Express**, and **PostgreSQL**, supporting both traditional email/password login and Google OAuth2 login. It includes:

* Email verification
* Password reset
* Session management
* Secure hashing using `bcrypt`



##  Technologies Used

* **Backend**: Node.js, Express.js
* **Authentication**: Passport.js (Local & Google OAuth2)
* **Database**: PostgreSQL
* **Security**: bcrypt for password hashing
* **Email**: Nodemailer with Gmail SMTP
* **Session Management**: express-session
* **Token Management**: uuid
* **Templating**: Static HTML
* **Environment Variables**: dotenv



##  Project Features

* User registration with email verification
* Login with:

  * Email & Password
  * Google Sign-In (OAuth2)
* Password reset via email
* Session-based login (expires after 24 hours)
* Secure password hashing with bcrypt
* Token-based email verification and password reset


##  Folder Structure

* project-root/
* ├── public/
* │   ├── html/              # Frontend HTML pages
* │   └── styles/            # CSS and static files
* ├── app.js                 # Main server file
* ├── package.json
* └── README.md


##  Setup & Run Locally

### 1. Clone the Repository


git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name


### 2. Install Dependencies


npm install


### 3. Configure Environment Variables

Create a `.env` file in the root directory:


## Database Config ##
* USER_NAME=your_db_user
* USER_PASS=your_db_password
* HOST_NAME=localhost
* DB_NAME=your_db_name
* DB_PORT=5432

## Session Secret ##
* SECRET_CODE=your_secret

## Google OAuth ##
* GOOGLE_CLIENT_ID=your_google_client_id
* GOOGLE_CLIENT_SECRET=your_google_client_secret

## Email (Gmail) ##
* EMAIL_USER=your_gmail_address
* EMAIL_PASS=your_gmail_app_password

>  **Note**: If you're using Gmail and have 2FA enabled, you must [generate an App Password](https://support.google.com/accounts/answer/185833?hl=en) and use that as `EMAIL_PASS`.



### 4. Set Up PostgreSQL

* Run the following SQL to create the `users` table:

* CREATE TABLE users (
  * id SERIAL PRIMARY KEY,
  * mail_id VARCHAR(255) UNIQUE NOT NULL,
  * password TEXT NOT NULL,
  * verified BOOLEAN DEFAULT false,
  * verification_token TEXT,
  * token_expires TIMESTAMP,
  * reset_token TEXT,
  * reset_token_expires TIMESTAMP
* );

### 5. Run the Server

* node app.js

* Server will start at: [http://localhost:3000](http://localhost:3000)


##  Testing Features

* Register at `/`
* Check verification email and click the link
* Login at `/login`
* Google login at `/auth/google`
* Reset password from `/forgetpass`
* Set password after Google login at `/setpass`

##  Security Notes

* Passwords are securely hashed with `bcrypt`
* Tokens for email verification & password reset are time-bound
* Sessions expire after 24 hours (`maxAge`)
* Emails are sent using secure SMTP via Gmail


##  Credits

Developed by **Tridip Kalita**.
