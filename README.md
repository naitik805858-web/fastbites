# FastBites Backend — Setup Guide

## 🔴 IMPORTANT: Permanent Database Setup (Turso) — Do this FIRST for hosting

Render's free tier **deletes local files on every redeploy**, so without this step, all
users/orders/menu items get wiped every time you push new code. Turso is a **free** cloud
database that fixes this permanently. Takes 5 minutes:

1. Go to **turso.tech** → Sign up (GitHub login is easiest)
2. Create a database (dashboard has a "Create Database" button — pick any name, e.g. `fastbites`)
3. On the database page, find:
   - **Database URL** (starts with `libsql://...`)
   - Click "Create Token" → copy the generated token
4. Go to your **Render dashboard** → your service → **Environment** tab → add two variables:
   - `TURSO_DATABASE_URL` = the URL you copied
   - `TURSO_AUTH_TOKEN` = the token you copied
5. Save — Render will redeploy automatically

That's it. From now on, **all data survives redeploys forever** — admin panel changes,
signups, orders, everything. If these two environment variables are NOT set, the app falls
back to a local SQLite file (fine only for quick testing in Termux, resets on every Render
redeploy).

## Chalane ka tarika (Kaise run kare — local testing, e.g. Termux)

1. **Node.js install hona chahiye** (version 22 ya usse upar). Check karo: `node --version`
2. Terminal me `backend` folder ke andar jao:
   ```
   cd backend
   ```
3. Dependencies install karo (sirf ek baar, internet chahiye):
   ```
   npm install
   ```
4. Server start karo:
   ```
   node server.js
   ```
5. Ye print hoga (agar Turso env vars set nahi hai to local SQLite file use hogi):
   ```
   🚀 FastBites backend running at http://localhost:4000
   👉 Admin panel: http://localhost:4000/admin/login.html
   ```
6. Terminal me upar ek box dikhega jisme **random admin password** hoga — usko turant save kar lo, sirf ek baar dikhta hai.

## Kya kya bana hai

- **Dashboard** — total users, total orders, pending payments, cancelled orders ka quick view
- **Users page** — sabhi customers: name, username, mobile, address + kitne order successful / cancelled kiye
- **Orders page** — har order ka payment mode (UPI/COD), payment status (Paid/Pending), delivery address, aur order status dropdown se update kar sakte ho: PLACED → PREPARING → COOKING → OUT_FOR_DELIVERY → DELIVERED / CANCELLED
- **Items & Categories page** — naya category banao, phir usme item add karo (naam, price, image link, description, full description, prep time, rating) — **ye turant customer app ke menu me dikhega**, koi extra step nahi
- **Banner page** — image link ya video link daal ke banner add karo, active/hidden toggle kar sakte ho

## Customer app (index.html) — ab poori tarah dynamic hai

- **Menu aur category tabs** ab backend se live load hote hain (`/api/public/menu`, `/api/public/categories`) — admin panel se item/category add/edit/delete karte hi customer app me turant dikhega (page refresh pe)
- **Trending section** automatically highest-rated items dikhata hai
- **Order history** account panel me poori details ke saath dikhta hai: har item ka naam/quantity/price, total, payment mode, delivery address, order kab kiya tha, aur latest status kab update hua
- **Home page order tracker** — jab bhi login hoke koi active order ho, header ke neeche ek progress-bar wala box dikhta hai jo har 30 second me automatically refresh hota hai
- **Account panel me order history** bhi har 20 second me refresh hoti hai jab panel khula ho

## Database
Turso configure karne ke baad sab data cloud me permanent save hota hai. Agar Turso configure nahi kiya, to local `backend/data/fastbites.db` file use hoti hai — sirf testing ke liye theek hai, Render pe redeploy hone se ye delete ho jayegi.

## Hosting ke liye zaroori steps (Security)

1. **Admin password automatic random generate hota hai** — pehli baar server start hone pe terminal/Render logs me dikhega. Turant save kar lo. Bhool jao to `node change-admin-password.js apna_naya_password` se reset kar sakte ho.

2. **`index.html` backend ke saath hi serve hota hai** — `backend/public/index.html` me hai. Server chalne pe customer app root URL pe (`https://tumhara-domain.com/`) aur admin panel `/admin/login.html` pe milega.

3. **HTTPS zaroor use karo** — Render free me automatic HTTPS deta hai.

4. **Already implemented security:**
   - Passwords salted PBKDF2 hashing se store hote hain
   - Login/signup pe brute-force protection — 8 galat attempts ke baad 15 min block
   - Har user ko login/signup pe ek **session token** milta hai — koi bhi sirf user ID guess karke kisi aur ka data edit ya order place nahi kar sakta
   - Admin login token-based, 24 ghante baad expire, "Logout" turant cancel karta hai
   - SQL injection se safe (sab queries parameterized)
   - Order placement rate-limited hai (spam bots se bachne ke liye)
   - Security headers sab responses me lagte hain
   - Server errors internal details client ko nahi dikhate

5. **Limitation:** signup pe mobile OTP verify nahi hota. Real business ke liye baad me OTP verification add karwa sakte ho.

