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

// 🔹 Connect to MongoDB
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
// 🎨 FRONTEND: HTML UI (Modern & Beautiful)
// ==========================================

// 1️⃣ LOGIN & REGISTER PAGE UI
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
                <input type="text" id="r_name" placeholder="Full Name">
                <input type="email" id="r_email" placeholder="Email Address">
                <input type="password" id="r_password" placeholder="Create Password">
                <select id="r_role">
                    <option value="customer">I am a Passenger</option>
                    <option value="driver">I am a Driver</option>
                </select>
                <button onclick="register()">Sign Up</button>
                <div class="toggle" onclick="toggleForms()">Already have an account? Log In</div>
            </div>
            
            <p id="errorMsg" class="error"></p>
        </div>

        <script>
            // Toggle between Login and Register
            function toggleForms() {
                document.getElementById('loginForm').classList.toggle('hidden');
                document.getElementById('regForm').classList.toggle('hidden');
                document.getElementById('errorMsg').style.display = 'none';
            }

            // LOGIN LOGIC
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
                        localStorage.setItem('user', email);
                        window.location.href = '/'; // Go to Dashboard
                    } else {
                        errorBox.innerText = data.error;
                        errorBox.style.display = 'block';
                    }
                } catch (e) {
                    errorBox.innerText = "Connection Error";
                    errorBox.style.display = 'block';
                }
            }

            // REGISTER LOGIC
            async function register() {
                const name = document.getElementById('r_name').value;
                const email = document.getElementById('r_email').value;
                const password = document.getElementById('r_password').value;
                const role = document.getElementById('r_role').value;
                const errorBox = document.getElementById('errorMsg');

                try {
                    const res = await fetch('/api/auth/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ name, email, password, role })
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

// 2️⃣ MAIN DASHBOARD UI
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Grab | Dashboard</title>
        <style>
            :root { --grab-green: #00B140; --dark: #1F1F1F; --gray: #F4F4F4; }
            body { font-family: 'Segoe UI', sans-serif; margin: 0; background: var(--gray); }
            
            /* Navbar */
            nav { background: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
            nav h2 { margin: 0; color: var(--grab-green); font-weight: 800; }
            nav .user-info { font-size: 14px; color: #555; }
            nav button { background: #eee; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; margin-left: 10px; font-weight: bold; }
            nav button:hover { background: #ddd; }

            /* Main Content */
            .container { max-width: 800px; margin: 40px auto; padding: 0 20px; }
            .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 5px 15px rgba(0,0,0,0.05); margin-bottom: 20px; text-align: center; }
            .card h3 { margin-top: 0; color: #333; }

            /* Action Buttons */
            .btn { background: var(--grab-green); color: white; padding: 12px 25px; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: 0.2s; display: inline-block; margin: 5px; }
            .btn:hover { background: #009e39; }
            .btn-sec { background: white; color: #333; border: 2px solid #ddd; }
            .btn-sec:hover { border-color: #bbb; }

            /* List */
            #listArea { text-align: left; margin-top: 20px; }
            .item { background: #f9f9f9; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid var(--grab-green); display: flex; justify-content: space-between; align-items: center; }
            .status { font-size: 12px; font-weight: bold; padding: 4px 8px; border-radius: 4px; background: #e0f7fa; color: #006064; }
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
                <h1 id="welcomeText">Welcome to Grab</h1>
                <p>Secure Ride Booking Platform</p>
                <div id="customerActions" style="display:none;">
                    <input type="text" id="pickup" placeholder="Pickup Location" style="padding:10px; width:45%; margin-right:5px;">
                    <input type="text" id="dropoff" placeholder="Destination" style="padding:10px; width:45%;">
                    <br><br>
                    <button class="btn" onclick="bookRide()">🚗 Book Ride (RM 15.00)</button>
                </div>
                <div id="driverActions" style="display:none;">
                    <button class="btn" onclick="fetchRides()">🔄 Refresh Job Board</button>
                </div>
            </div>

            <div id="listArea"></div>
        </div>

        <script>
            const token = localStorage.getItem('token');
            const role = localStorage.getItem('role');
            const user = localStorage.getItem('user');

            // 🔒 SECURITY CHECK: If no token, kick to login
            if (!token) {
                window.location.href = '/login';
            } else {
                document.getElementById('displayUser').innerText = user + " (" + role.toUpperCase() + ")";
                
                // Show buttons based on Role
                if (role === 'customer') {
                    document.getElementById('customerActions').style.display = 'block';
                    document.getElementById('welcomeText').innerText = "Where to today?";
                    fetchTrack(); // Check if user has active rides
                } else if (role === 'driver') {
                    document.getElementById('driverActions').style.display = 'block';
                    document.getElementById('welcomeText').innerText = "Ready to drive?";
                    fetchRides(); // Load jobs immediately
                }
            }

            function logout() {
                localStorage.clear();
                window.location.href = '/login';
            }

            // --- CUSTOMER FUNCTIONS ---
            async function bookRide() {
                const pickup = document.getElementById('pickup').value;
                const destination = document.getElementById('dropoff').value;

                if(!pickup || !destination) return alert("Please enter locations!");

                const res = await fetch('/api/rides', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pickup, destination, price: 15 })
                });

                if(res.ok) {
                    alert("✅ Finding you a driver...");
                    fetchTrack();
                } else {
                    alert("Failed to book.");
                }
            }

            async function fetchTrack() {
                // For demo, we just list "Your Recent Rides" logic here or simple list
                // Since there is no "List my rides" endpoint in your table, we skip for now 
                // or you can add one. For now, we leave empty to keep it crash-free.
            }

            // --- DRIVER FUNCTIONS ---
            async function fetchRides() {
                const res = await fetch('/api/rides/available', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const rides = await res.json();
                
                const list = document.getElementById('listArea');
                list.innerHTML = '<h3>Available Jobs</h3>';

                if(rides.length === 0) list.innerHTML += '<p>No rides available right now.</p>';

                rides.forEach(r => {
                    list.innerHTML += \`
                        <div class="item">
                            <div>
                                <strong>\${r.pickup} ➝ \${r.destination}</strong><br>
                                <small>RM \${r.price}</small>
                            </div>
                            <button class="btn-sec" onclick="acceptRide('\${r._id}')">Accept</button>
                        </div>
                    \`;
                });
            }

            async function acceptRide(id) {
                const res = await fetch(\`/api/rides/\${id}/accept\`, {
                    method: 'PATCH',
                    headers: { 'Authorization': 'Bearer ' + token }
                });

                if(res.ok) {
                    alert("✅ Ride Accepted! Go pick them up.");
                    fetchRides(); // Refresh list
                } else {
                    alert("Error accepting ride.");
                }
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
        const { name, email, password, role } = req.body; 
        if (!email || !password || !role) return res.status(400).json({ error: 'Fields required' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { name, email, password: hashedPassword, role, createdAt: new Date() };
        
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
        res.json({ token, role: user.role, userId: user._id });
    } catch (err) {
        res.status(500).json({ error: "Login failed" });
    }
});

// ==========================================
// 🚕 CUSTOMER USE CASES
// ==========================================

app.post('/api/rides', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'customer') return res.status(403).json({ error: "Only customers can book" });

        const { pickup, destination, price } = req.body;
        
        const ride = {
            customerId: new ObjectId(req.user.userId),
            pickup,
            destination,
            price,
            status: "pending", 
            paymentStatus: "unpaid",
            createdAt: new Date()
        };

        const result = await db.collection('rides').insertOne(ride);
        res.status(201).json({ message: "Ride requested", rideId: result.insertedId });

    } catch (err) {
        res.status(400).json({ error: "Bad Request" });
    }
});

app.get('/api/rides/:id/track', verifyToken, async (req, res) => {
    try {
        const ride = await db.collection('rides').findOne({ _id: new ObjectId(req.params.id) });
        if (!ride) return res.status(404).json({ error: "Ride not found" });

        let driverInfo = "Waiting for driver...";
        if (ride.driverId) {
            const driver = await db.collection('users').findOne({ _id: new ObjectId(ride.driverId) });
            driverInfo = { name: driver.name, location: "En route (Simulated)" };
        }

        res.status(200).json({ status: ride.status, driver: driverInfo });

    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

app.patch('/api/rides/:id/cancel', verifyToken, async (req, res) => {
    try {
        const rideId = new ObjectId(req.params.id);
        const ride = await db.collection('rides').findOne({ _id: rideId });

        if (!ride) return res.status(404).json({ error: "Not Found" });
        if (ride.status === 'completed') return res.status(409).json({ error: "Cannot cancel completed ride" });

        await db.collection('rides').updateOne(
            { _id: rideId },
            { $set: { status: "cancelled" } }
        );
        res.status(200).json({ message: "Ride cancelled" });

    } catch (err) {
        res.status(400).json({ error: "Error cancelling ride" });
    }
});

app.post('/api/rides/:id/payment', verifyToken, async (req, res) => {
    try {
        const { amount, method } = req.body; 
        const rideId = new ObjectId(req.params.id);

        if (!amount) return res.status(402).json({ error: "Payment Required" });

        await db.collection('rides').updateOne(
            { _id: rideId },
            { $set: { paymentStatus: "paid", paymentMethod: method } }
        );

        res.status(201).json({ message: "Payment successful" });

    } catch (err) {
        res.status(400).json({ error: "Payment failed" });
    }
});

app.post('/api/rides/:id/review', verifyToken, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const rideId = new ObjectId(req.params.id);

        const ride = await db.collection('rides').findOne({ _id: rideId });
        if (!ride) return res.status(404).json({ error: "Ride not found" });

        const review = {
            rideId,
            driverId: ride.driverId,
            customerId: req.user.userId,
            rating,
            comment,
            createdAt: new Date()
        };

        await db.collection('reviews').insertOne(review);
        res.status(201).json({ message: "Review submitted" });

    } catch (err) {
        res.status(400).json({ error: "Error submitting review" });
    }
});

// ==========================================
// 🛵 DRIVER USE CASES
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
        const ride = await db.collection('rides').findOne({ _id: rideId });

        if (!ride) return res.status(404).json({ error: "Not Found" });
        if (ride.status !== "pending") return res.status(409).json({ error: "Ride already taken" });

        await db.collection('rides').updateOne(
            { _id: rideId },
            { $set: { status: "accepted", driverId: new ObjectId(req.user.userId) } }
        );

        res.status(200).json({ message: "Ride accepted" });

    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

app.get('/api/driver/:id/earning', verifyToken, async (req, res) => {
    try {
        const driverId = new ObjectId(req.params.id);

        const stats = await db.collection('rides').aggregate([
            { $match: { driverId: driverId, status: "completed" } },
            { $group: { _id: null, totalEarnings: { $sum: "$price" } } }
        ]).toArray();

        const total = stats.length > 0 ? stats[0].totalEarnings : 0;
        res.status(200).json({ driverId, totalEarnings: total });

    } catch (err) {
        res.status(404).json({ error: "Driver not found" });
    }
});

// ==========================================
// 🛡️ ADMIN USE CASES
// ==========================================

app.patch('/api/admin/users/:id', verifyToken, requireAdmin, async (req, res) => {
    try {
        const { blocked } = req.body; 
        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { blocked: blocked } }
        );

        if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });
        res.status(200).json({ message: "User updated" });

    } catch (err) {
        res.status(403).json({ error: "Forbidden" });
    }
});

app.get('/api/admin/rides', verifyToken, requireAdmin, async (req, res) => {
    try {
        const rides = await db.collection('rides').find().toArray();
        res.status(200).json(rides);
    } catch (err) {
        res.status(401).json({ error: "Unauthorized" });
    }
});

app.delete('/api/admin/reviews/:id', verifyToken, requireAdmin, async (req, res) => {
    try {
        const result = await db.collection('reviews').deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Not Found" });

        res.status(204).send(); 
    } catch (err) {
        res.status(403).json({ error: "Forbidden" });
    }
});

app.get('/api/admin/reports', verifyToken, requireAdmin, async (req, res) => {
    try {
        const totalRides = await db.collection('rides').countDocuments();
        const totalRevenue = await db.collection('rides').aggregate([
            { $group: { _id: null, total: { $sum: "$price" } } }
        ]).toArray();

        res.status(200).json({
            reportDate: new Date(),
            totalRides,
            totalRevenue: totalRevenue[0]?.total || 0
        });
    } catch (err) {
        res.status(401).json({ error: "Unauthorized" });
    }
});

// Start Server
connectDB().then(() => {
    app.listen(port, () => {
        console.log(`🚀 Grab Backend running on port ${port}`);
    });
});