# Simple JWT Token Service (MINI SSO)

This project is a JWT-based token service built using **Go**, **PostgreSQL**, and Docker. The service supports issuing and refreshing JWT tokens, along with a secure implementation of refresh tokens stored in the database.
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
