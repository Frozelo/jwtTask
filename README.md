# Simple JWT Token Service (MINI SSO)

This project is a JWT-based token service built using **Go**, **PostgreSQL**, and **Docker**. The service supports issuing and refreshing JWT tokens, along with a secure implementation of refresh tokens stored in the database.
It`s like SSO but mini version. Working with JWT tokens and refresh tokens.

---

## **Features**

1. **JWT Access Tokens**:
   - Access tokens are signed with the SHA-512 algorithm.
   - Tokens are stateless and not stored in the database.

2. **Secure Refresh Tokens**:
   - Refresh tokens are stored as bcrypt hashes in the database.
   - Tokens are linked to access tokens and cannot be reused once invalidated.

3. **IP Change Warning**:
   - If the client IP changes during the refresh process, a warning is logged to simulate sending an email.

4. **Docker Support**:
   - Includes a Dockerized setup for both the application and the PostgreSQL database.

5. **Configurable**:
   - Environment variables control database and JWT configuration.

6. **Swagger UI**:
   - API documentation is available through Swagger UI.

7. **Logging**:
    - Logs are written to the console in json format.

8. **Testing**:
    - Unit tests are included for the service layer.

---

## **Getting Started**

### **Prerequisites**

Ensure you have the following installed:

- Docker

---

## **Setup and Running the Application**

### **1. Clone the repository**

```bash
git clone https://github.com/your-repo/jwt-auth-service.git
cd jwtTask
```

### **2. Env configuration**

Create a `.env` file in the root directory and add the following environment variables:

```env
POSTGRES_HOST        # Database host (e.g., 'localhost' or 'db' for Docker)
POSTGRES_USER        # Database username
POSTGRES_PASSWORD    # Database password
POSTGRES_DB          # Name of the database
PORT                 # Port on which the application runs
DB_SSLMODE           # SSL mode for database connection (e.g., 'disable', 'require')
JWT_SECRET           # Secret key used for signing JWT tokens
JWT_ISSUER           # Issuer field included in JWT tokens
```

### **3. Build and run the Docker containers**

```bash
docker-compose up --build
```

### **4. Access the application**

The application will be running on `http://localhost:8080` (by default).
You can use Swagger UI to interact with the API by visiting `http://localhost:8080/swagger/index.html`.

Or using curl:

**Issue token**
```bash
curl -X POST http://localhost:8080/issue \
-H "Content-Type: application/json" \
-d '{
    "user_id": "your-uuid"
}'
```

**Refresh token**
```bash
curl -X POST http://localhost:8080/refresh \
-H "Content-Type: application/json" \
-d '{
    "access_token": "your-access-token",
    "refresh_token": "your-refresh-token"
}'
```
