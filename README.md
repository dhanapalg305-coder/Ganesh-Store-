# Ganesh Cookware — Secure Online Admin + Database

This project upgrades the static store to a real server-backed application. Products, prices, pictures, store settings and server sessions are stored in SQLite. Admin authentication uses bcrypt password hashing, server sessions, CSRF protection, rate limiting, secure cookies in production, Helmet security headers, upload validation and a non-public database file.

## 1. Configure
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Set `SESSION_SECRET` to a random 32+ character secret.
4. Set `ADMIN_EMAIL` to the admin email and `ADMIN_PASSWORD` to the strong admin password you want to use. Do not commit `.env`.

## 2. Run
```bash
npm install
npm start
```
Open `http://localhost:3000/` for the store and `http://localhost:3000/admin` for the admin dashboard.

## 3. Online deployment
Use a Node.js host such as Render, Railway, Fly.io, VPS, or another platform that supports a persistent disk. Set the environment variables from `.env` in the host dashboard. **Attach persistent storage** because SQLite and uploaded images are stored under `data/`.

For a production domain, serve the app over HTTPS. The session cookie automatically becomes `Secure` when `NODE_ENV=production`.

## Admin capabilities
- Add/edit/delete products
- Change product name, category, description
- Upload/change product picture
- Change selling price
- Change current market/reference price
- Change hero picture and store details
- Database-backed authentication
- Logout, session expiry and password change

## Security notes
- The password is never stored in plaintext in the database; it is bcrypt-hashed.
- The frontend never contains the admin password or password hash.
- Login is rate-limited.
- Mutating admin requests require a session-bound CSRF token.
- Image uploads are limited to 5 MB and checked by file signature.
- Do not expose the SQLite database file or `.env` publicly.
- Back up `data/ganesh.sqlite` and `data/uploads/` regularly.
