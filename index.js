require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 8080;
let db;

// 🔹 Connect to MongoDB (MyTaxi / GrabDB)
async function connectDB() {
    const uri = process.env.MONGO_URI || "mongodb://127.0.0.1:27017";
    const client = new MongoClient(uri);
    await client.connect();
    db = client.db("grabDB");
    console.log("✅ Connected to MongoDB (grabDB)");
}

// 🔹 Middleware: Verify Token
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ error: 'Invalid token format' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
}

// 🔹 Middleware: Admin Only
function requireAdmin(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Admin access only" });
    }
    next();
}

// ==========================================
// 🎨 FRONTEND: MODERN UI (Green Theme)
// ==========================================

// 1️⃣ LOGIN & REGISTER PAGE
app.get('/login', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Grab | Login</title>
        <style>
            :root { --grab-green: #00B140; --dark: #1F1F1F; --light: #F4F4F4; }
            body { font-family: 'Segoe UI', sans-serif; background: var(--light); display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
            h1 { color: var(--grab-green); font-weight: 800; letter-spacing: -1px; margin-bottom: 20px; }
            input, select { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; background: #fafafa; }
            button { width: 100%; padding: 12px; background: var(--grab-green); color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; margin-top: 15px; font-size: 16px; transition: 0.2s; }
            button:hover { background: #009e39; }
            .toggle { margin-top: 20px; font-size: 14px; color: #666; cursor: pointer; text-decoration: underline; }
            .error { color: red; font-size: 13px; margin-top: 10px; display: none; }
            .hidden { display: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Grab</h1>
            
            <div id="loginForm">
                <h3 style="color:#444;">Welcome Back</h3>
                <input type="email" id="l_email" placeholder="Email Address">
                <input type="password" id="l_password" placeholder="Password">
                <button onclick="login()">Log In</button>
                <div class="toggle" onclick="toggleForms()">New here? Create Account</div>
            </div>

            <div id="regForm" class="hidden">
                <h3 style="color:#444;">Join Grab</h3>
                <input type="text" id="r_username" placeholder="Username (e.g. Alvinc2)">
                <input type="email" id="r_email" placeholder="Email Address">
                <input type="password" id="r_password" placeholder="Create Password">
                <select id="r_role">
                    <option value="customer">I am a Passenger</option>
                    <option value="driver">I am a Driver</option>
                    <option value="admin">Admin (Staff)</option>
                </select>
                <button onclick="register()">Sign Up</button>
                <div class="toggle" onclick="toggleForms()">Already have an account? Log In</div>
            </div>
            
            <p id="errorMsg" class="error"></p>
        </div>

        <script>
            function toggleForms() {
                document.getElementById('loginForm').classList.toggle('hidden');
                document.getElementById('regForm').classList.toggle('hidden');
                document.getElementById('errorMsg').style.display = 'none';
            }

            async function login() {
                const email = document.getElementById('l_email').value;
                const password = document.getElementById('l_password').value;
                const errorBox = document.getElementById('errorMsg');

                try {
                    const res = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    const data = await res.json();
                    
                    if (res.ok) {
                        localStorage.setItem('token', data.token);
                        localStorage.setItem('role', data.role);
                        localStorage.setItem('user', data.username || email);
                        window.location.href = '/'; 
                    } else {
                        errorBox.innerText = data.error;
                        errorBox.style.display = 'block';
                    }
                } catch (e) {
                    errorBox.innerText = "Connection Error";
                    errorBox.style.display = 'block';
                }
            }

            async function register() {
                const username = document.getElementById('r_username').value;
                const email = document.getElementById('r_email').value;
                const password = document.getElementById('r_password').value;
                const role = document.getElementById('r_role').value;
                const errorBox = document.getElementById('errorMsg');

                try {
                    const res = await fetch('/api/auth/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, email, password, role })
                    });
                    
                    if (res.ok) {
                        alert("Account created! Please log in.");
                        toggleForms();
                    } else {
                        const data = await res.json();
                        errorBox.innerText = data.error || "Registration failed";
                        errorBox.style.display = 'block';
                    }
                } catch (e) {
                    errorBox.innerText = "Connection Error";
                    errorBox.style.display = 'block';
                }
            }
        </script>
    </body>
    </html>
    `);
});

// 2️⃣ MAIN DASHBOARD UI (Smart Logic)
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Grab | Dashboard</title>
        <style>
            :root { --grab-green: #00B140; --dark: #1F1F1F; --gray: #F4F4F4; --danger: #dc3545; }
            body { font-family: 'Segoe UI', sans-serif; margin: 0; background: var(--gray); }
            
            nav { background: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
            nav h2 { margin: 0; color: var(--grab-green); font-weight: 800; }
            nav .user-info { font-size: 14px; color: #555; }
            nav button { background: #eee; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; margin-left: 10px; font-weight: bold; }
            
            .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
            .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 5px 15px rgba(0,0,0,0.05); margin-bottom: 20px; text-align: center; }
            
            .btn { background: var(--grab-green); color: white; padding: 12px 25px; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: 0.2s; display: inline-block; margin: 5px; }
            .btn:hover { background: #009e39; }
            .btn-danger { background: var(--danger); }
            .btn-danger:hover { background: #c82333; }
            
            .item { background: #f9f9f9; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid var(--grab-green); display: flex; justify-content: space-between; align-items: center; text-align: left; }
            input { padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin: 5px; width: 30%; }
        </style>
    </head>
    <body>
        <nav>
            <h2>Grab</h2>
            <div class="user-info">
                <span id="displayUser">Guest</span>
                <button onclick="logout()">Logout</button>
            </div>
        </nav>

        <div class="container">
            <div class="card">
                <h1 id="welcomeText">Welcome</h1>
                <p id="subText">Secure Ride Booking Platform</p>
                
                <div id="customerActions" style="display:none;">
                    <input type="text" id="pickup" placeholder="Pickup Location">
                    <input type="text" id="dropoff" placeholder="Destination">
                    <input type="number" id="distance" placeholder="Dist (km)" style="width: 15%">
                    <br><br>
                    <button class="btn" onclick="bookRide()">🚗 Book Ride</button>
                    <p style="font-size: 12px; color: #888;">*Fare is calculated at RM 2.00 per KM</p>
                </div>

                <div id="driverActions" style="display:none;">
                    <button class="btn" onclick="fetchRides()">🔄 Refresh Job Board</button>
                </div>

                <div id="adminActions" style="display:none;">
                    <button class="btn" onclick="fetchUsers()">👥 Manage Users</button>
                    <button class="btn" onclick="fetchReports()">📊 View Analytics</button>
                </div>
            </div>

            <div id="listArea"></div>
        </div>

        <script>
            const token = localStorage.getItem('token');
            const role = localStorage.getItem('role');
            const user = localStorage.getItem('user');

            if (!token) window.location.href = '/login';

            document.getElementById('displayUser').innerText = user + " (" + role.toUpperCase() + ")";

            // --- UI SETUP BASED ON ROLE ---
            if (role === 'customer') {
                document.getElementById('customerActions').style.display = 'block';
                document.getElementById('welcomeText').innerText = "Where to today, " + user + "?";
            } else if (role === 'driver') {
                document.getElementById('driverActions').style.display = 'block';
                document.getElementById('welcomeText').innerText = "Ready to earn, " + user + "?";
                fetchRides();
            } else if (role === 'admin') {
                document.getElementById('adminActions').style.display = 'block';
                document.getElementById('welcomeText').innerText = "Admin Dashboard";
                document.getElementById('subText').innerText = "Manage Users & System Analytics";
                fetchUsers();
            }

            function logout() { localStorage.clear(); window.location.href = '/login'; }

            // --- CUSTOMER LOGIC ---
            async function bookRide() {
                const pickup = document.getElementById('pickup').value;
                const destination = document.getElementById('dropoff').value;
                const distance = document.getElementById('distance').value;

                if(!pickup || !destination || !distance) return alert("Fill all fields!");

                const fare = (distance * 2).toFixed(2); // Simple Logic: RM 2 per KM

                const res = await fetch('/api/rides', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pickup, destination, distance, fare })
                });

                if(res.ok) alert("✅ Ride Booked! Fare: RM " + fare);
                else alert("Booking Failed");
            }

            // --- DRIVER LOGIC ---
            async function fetchRides() {
                const res = await fetch('/api/rides/available', { headers: { 'Authorization': 'Bearer ' + token } });
                const rides = await res.json();
                const list = document.getElementById('listArea');
                list.innerHTML = '<h3>Available Jobs</h3>';
                if(rides.length === 0) list.innerHTML += '<p>No jobs currently available.</p>';
                
                rides.forEach(r => {
                    list.innerHTML += \`
                        <div class="item">
                            <div>
                                <strong>\${r.pickup} ➝ \${r.destination}</strong><br>
                                <small>\${r.distance} km • <b style="color:green">RM \${r.fare}</b></small>
                            </div>
                            <button class="btn" onclick="acceptRide('\${r._id}')">Accept</button>
                        </div>
                    \`;
                });
            }

            async function acceptRide(id) {
                const res = await fetch(\`/api/rides/\${id}/accept\`, { method: 'PATCH', headers: { 'Authorization': 'Bearer ' + token } });
                if(res.ok) { alert("Ride Accepted!"); fetchRides(); }
            }

            // --- ADMIN LOGIC ---
            async function fetchUsers() {
                const res = await fetch('/api/admin/users', { headers: { 'Authorization': 'Bearer ' + token } });
                const users = await res.json();
                const list = document.getElementById('listArea');
                list.innerHTML = '<h3>User Management</h3>';
                
                users.forEach(u => {
                    list.innerHTML += \`
                        <div class="item">
                            <div>
                                <strong>\${u.username}</strong> (\${u.role})<br>
                                <small>\${u.email}</small>
                            </div>
                            <button class="btn btn-danger" onclick="deleteUser('\${u._id}')">Delete</button>
                        </div>
                    \`;
                });
            }

            async function deleteUser(id) {
                if(!confirm("Are you sure you want to delete this user?")) return;
                const res = await fetch(\`/api/admin/users/\${id}\`, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + token } });
                if(res.ok) fetchUsers();
            }

            async function fetchReports() {
                const res = await fetch('/api/admin/reports', { headers: { 'Authorization': 'Bearer ' + token } });
                const data = await res.json();
                const list = document.getElementById('listArea');
                list.innerHTML = \`
                    <h3>System Analytics</h3>
                    <div style="display:flex; justify-content:space-around; margin-top:20px;">
                        <div style="background:#e0f7fa; padding:20px; border-radius:10px; width:45%;">
                            <h1>\${data.totalRides}</h1>
                            <p>Total Rides</p>
                        </div>
                        <div style="background:#fff3cd; padding:20px; border-radius:10px; width:45%;">
                            <h1>RM \${data.totalRevenue}</h1>
                            <p>Total Revenue</p>
                        </div>
                    </div>
                \`;
            }
        </script>
    </body>
    </html>
    `);
});

// ==========================================
// 🔐 AUTHENTICATION ENDPOINTS
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body; 
        if (!email || !password || !role) return res.status(400).json({ error: 'Fields required' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { username, email, password: hashedPassword, role, createdAt: new Date() };
        
        await db.collection('users').insertOne(newUser);
        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        res.status(500).json({ error: "Error registering user" });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await db.collection('users').findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
        // Return username so frontend can display it
        res.json({ token, role: user.role, userId: user._id, username: user.username });
    } catch (err) {
        res.status(500).json({ error: "Login failed" });
    }
});

// ==========================================
// 🚕 CUSTOMER ENDPOINTS
// ==========================================

app.post('/api/rides', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'customer') return res.status(403).json({ error: "Only customers can book" });

        const { pickup, destination, distance, fare } = req.body; // Updated to match MyTaxi Schema
        
        const ride = {
            customerId: new ObjectId(req.user.userId),
            pickup,
            destination,
            distance: parseFloat(distance),
            fare: parseFloat(fare),
            status: "pending", 
            createdAt: new Date()
        };

        const result = await db.collection('rides').insertOne(ride);
        res.status(201).json({ message: "Ride requested", rideId: result.insertedId });
    } catch (err) {
        res.status(400).json({ error: "Bad Request" });
    }
});

// ==========================================
// 🛵 DRIVER ENDPOINTS
// ==========================================

app.get('/api/rides/available', verifyToken, async (req, res) => {
    if (req.user.role !== 'driver') return res.status(401).json({ error: "Unauthorized" });
    const rides = await db.collection('rides').find({ status: "pending" }).toArray();
    res.status(200).json(rides);
});

app.patch('/api/rides/:id/accept', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'driver') return res.status(401).json({ error: "Unauthorized" });
        const rideId = new ObjectId(req.params.id);
        
        await db.collection('rides').updateOne(
            { _id: rideId },
            { $set: { status: "accepted", driverId: new ObjectId(req.user.userId) } }
        );
        res.status(200).json({ message: "Ride accepted" });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// ==========================================
// 🛡️ ADMIN ENDPOINTS (New Additions)
// ==========================================

// GET ALL USERS (For Admin Dashboard)
app.get('/api/admin/users', verifyToken, requireAdmin, async (req, res) => {
    const users = await db.collection('users').find().toArray();
    res.status(200).json(users);
});

// DELETE USER (For Admin Dashboard)
app.delete('/api/admin/users/:id', verifyToken, requireAdmin, async (req, res) => {
    await db.collection('users').deleteOne({ _id: new ObjectId(req.params.id) });
    res.status(200).json({ message: "User deleted" });
});

app.get('/api/admin/reports', verifyToken, requireAdmin, async (req, res) => {
    const totalRides = await db.collection('rides').countDocuments();
    const totalRevenue = await db.collection('rides').aggregate([
        { $group: { _id: null, total: { $sum: "$fare" } } } // Summing 'fare' now
    ]).toArray();

    res.status(200).json({
        totalRides,
        totalRevenue: totalRevenue[0]?.total || 0
    });
});

// Start Server
connectDB().then(() => {
    app.listen(port, () => {
        console.log(`🚀 Grab Backend running on port ${port}`);
    });
});
