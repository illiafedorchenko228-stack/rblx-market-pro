# RBLX Market Pro (v3.0)

A full-stack demo marketplace built with Express + PostgreSQL. Files are intentionally in the repository root: **no `public/` folder is needed**.

## Features
- Email/password registration and login; bcrypt password hashing; JWT sessions
- PostgreSQL tables created automatically on first successful server start
- Profiles, balance, product listings and demo purchases
- Trade offers
- User-to-user text chat
- Support tickets and admin replies/status updates
- Admin user list, block/unblock, and audit log
- Responsive dark/light interface
- Demo balance of 1,000,000 virtual rubles for each new account

## Required environment variables
Configure these in your hosting dashboard (do not commit real secrets):
- `DATABASE_URL`: PostgreSQL connection string from Supabase
- `DATABASE_SSL`: `true` for hosted Supabase PostgreSQL
- `JWT_SECRET`: long random secret (at least 32 random characters recommended)
- `ADMIN_EMAIL`: the email that should receive the ADMIN role when registering

The email in `ADMIN_EMAIL` becomes admin only at registration time. If the account already exists, do not delete production data or expose the database; ask for a safe admin-role migration.

## Deploy on Render
1. Create a Supabase PostgreSQL project and copy its connection string. Use a connection method compatible with your hosting region; if direct connection does not work, use Supabase's pooler connection string.
2. Create a new GitHub repository and upload all files in this ZIP **directly to the repository root**.
3. On Render create a Web Service connected to the repo.
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Choose the Free instance if available.
7. In Render > Environment add `DATABASE_URL`, `DATABASE_SSL=true`, `JWT_SECRET`, and `ADMIN_EMAIL`.
8. Deploy and check `https://YOUR-SERVICE.onrender.com/api/health`. Expected: `{"ok":true,"database":"connected"}`.

## Run locally (optional)
- Install Node.js 20+.
- Copy `.env.example` to `.env` and fill the values.
- Run `npm install`, then `npm start`.
- Open `http://localhost:3000`.

## Notes and limitations
- This is a demo marketplace, not a real-money payment system. Purchases transfer virtual demo balance only.
- No Roblox passwords or account credentials should ever be collected.
- Admin access must be configured with environment variables. Do not commit `.env` or secrets to GitHub.
- A public production marketplace needs further security review, moderation, backups, dispute handling, privacy/legal review and proper monitoring before real users or payments.
- Free hosting/database tiers have limits and may pause inactive projects.
