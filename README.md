# BriefBay — Pre-Release Early Access Portal (Secured & Production-Ready)

A clean, high-performance pre-release portal styled to match the official **BriefBay** brand identity (`#0B1E36` Deep Navy & `#2563EB` Electric Blue).

---

## 🔒 Administrative Access (Private & Password Protected)

The Admin Dashboard is **hidden from the public** and protected with username & password authentication.

- **Admin URL**: [http://localhost:4000#admin](http://localhost:4000#admin)
- **Admin Username**: `admin`
- **Admin Password**: `briefbayadmin2027`

*(Credentials can be updated anytime in [`c:\Users\Burhan Khan\Desktop\pre\.env`](file:///c:/Users/Burhan%20Khan/Desktop/pre/.env))*

### Admin Features:
1. **View All Registrations**: Filter by `All`, `⭐ First 15 VIPs`, `Clients`, `Freelancers`, or live search.
2. **First 15 VIP Highlighting**: Golden left accent border, VIP badge, and perk tags.
3. **Remove from Top 15**: For any user in the top 15, click the **"Remove from Top 15"** button. This demotes the user to standard access and instantly updates both the JSON registry and the main marketplace database (`dev.db`).
4. **Sync to DB**: One-click manual synchronization to `dev.db`.
5. **Export CSV**: Download complete registry data.

---

## 🛡️ Security Hardening Implemented

1. **HTTP Security Headers**:
   - `Content-Security-Policy`: Restricts unauthorized scripts and frame injection.
   - `X-Frame-Options: DENY`: Prevents clickjacking attacks.
   - `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing exploits.
   - `X-XSS-Protection: 1; mode=block`: Active browser cross-site scripting filter.
   - `Referrer-Policy: strict-origin-when-cross-origin`: Protects sensitive referrers.
2. **Brute Force & Rate Limiting**:
   - `POST /api/register`: Limited to max 5 registrations per IP per 10 minutes.
   - `POST /api/admin/login`: Limited to max 5 attempts per IP. Automatically locks for 15 minutes after 5 failed attempts.
   - Global API limit: Max 120 requests/minute per IP.
3. **DoS & Buffer Overflow Protection**:
   - Request body limit capped at 50KB to stop memory exhaustion attacks.
4. **Timing-Attack Resistance**:
   - Admin credentials verified using `crypto.timingSafeEqual`.
5. **Secure Cryptographic Sessions**:
   - Admin sessions use 256-bit cryptographically secure tokens stored in `sessionStorage` (auto-clears on tab close).
6. **SQL Injection Immune**:
   - Parameterized queries throughout `sync-db.js`.
7. **Input Validation**:
   - Strict regex for email (RFC 5322) and username (`^[a-zA-Z0-9_]{3,24}$`).

---

## 🔑 Google OAuth Credentials

Configured in `.env`:
- **Authorized JavaScript Origins**: `http://localhost:4000`
- **Authorized Redirect URIs**: `http://localhost:4000/auth/google/callback`

---

## 🚀 The 4-Step Registration Flow

1. **Step 1: Sign in with Google (or Direct Email)**
   - Click **"Sign in with Google"** to use live Google OAuth.
   - Or enter any email address directly in real time.
2. **Step 2: Account Creation**
   - Enter your `@username`.
   - Enter your **Password**: hidden by default with an interactive **Eye Icon** to view/hide.
3. **Step 3: Role & First 15 VIP Offers**
   - Select **Client / Creator** or **Freelancer**:
     - **Client Offer**: First 15 clients get **25% OFF on their first purchase**.
     - **Freelancer Offer**: First 15 freelancers get their **gigs & works featured or promoted**.
   - Confirm email and join.
4. **Step 4: Congratulations & Founding Pass**
   - Displays the clean Founding Pass card with unique ID and unlocked VIP perks.
   - Clean guidance note: *"Login with the same mail id used to register here to access your account on the main marketplace."*
   - **Automatic Redirect to Coming Soon**: Automatically redirects to `/coming-soon` after 3 seconds (or instantly via the "Continue" button).
5. **Step 5: Coming Soon Glitched Page (`/coming-soon`)**
   - Displays **BriefBay with the official logo**.
   - Features a large **`COMING SOON`** with an authentic cyberpunk / chromatic aberration **glitched text effect**.

---

## 💻 How to Start the Server

```powershell
cd "c:\Users\Burhan Khan\Desktop\pre"
node server.js
```
- **Public Portal**: [http://localhost:4000](http://localhost:4000)
- **Admin Portal**: [http://localhost:4000#admin](http://localhost:4000#admin)
