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
    db = client.db("grabDB"); // Changed to GrabDB
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

// 🟢 ROOT: Simple Status Check
app.get('/', (req, res) => {
    res.send("<h1>🟢 Grab Backend is Running!</h1><p>Use Postman to test /api/ endpoints.</p>");
});

// ==========================================
// 🔐 AUTHENTICATION (Required for the app to work)
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body; // Role: customer, driver, admin
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
// 🚕 CUSTOMER USE CASES (Table 4)
// ==========================================

// 1. Customer: Book Ride -> POST /api/rides
app.post('/api/rides', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'customer') return res.status(403).json({ error: "Only customers can book" });

        const { pickup, destination, price } = req.body;
        
        const ride = {
            customerId: new ObjectId(req.user.userId),
            pickup,
            destination,
            price,
            status: "pending", // pending, accepted, completed, cancelled
            paymentStatus: "unpaid",
            createdAt: new Date()
        };

        const result = await db.collection('rides').insertOne(ride);
        res.status(201).json({ message: "Ride requested", rideId: result.insertedId });

    } catch (err) {
        res.status(400).json({ error: "Bad Request" });
    }
});

// 2. Customer: Track Driver -> GET /api/rides/:id/track
app.get('/api/rides/:id/track', verifyToken, async (req, res) => {
    try {
        const ride = await db.collection('rides').findOne({ _id: new ObjectId(req.params.id) });
        if (!ride) return res.status(404).json({ error: "Ride not found" });

        // If driver exists, get their info
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

// 3. Customer: Cancel Ride -> PATCH /api/rides/:id/cancel
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

// 4. Customer: Make Payment -> POST /api/rides/:id/payment
app.post('/api/rides/:id/payment', verifyToken, async (req, res) => {
    try {
        const { amount, method } = req.body; // e.g. Credit Card
        const rideId = new ObjectId(req.params.id);

        // Simple validation mock
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

// 5. Customer: Rate & Review -> POST /api/rides/:id/review
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
// 🛵 DRIVER USE CASES (Table 4)
// ==========================================

// 6. Driver: View Ride Requests -> GET /api/rides/available
app.get('/api/rides/available', verifyToken, async (req, res) => {
    if (req.user.role !== 'driver') return res.status(401).json({ error: "Unauthorized" });

    const rides = await db.collection('rides').find({ status: "pending" }).toArray();
    res.status(200).json(rides);
});

// 7. Driver: Accept Ride -> PATCH /api/rides/:id/accept
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

// 8. Driver: View Earnings -> GET /api/driver/:id/earning
app.get('/api/driver/:id/earning', verifyToken, async (req, res) => {
    try {
        const driverId = new ObjectId(req.params.id);

        // Calculate total earnings from completed rides
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
// 🛡️ ADMIN USE CASES (Table 4 continued)
// ==========================================

// 9. Admin: Manage Users (Block/Update) -> PATCH /api/admin/users/:id
app.patch('/api/admin/users/:id', verifyToken, requireAdmin, async (req, res) => {
    try {
        const { blocked } = req.body; // Send { "blocked": true }
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

// 10. Admin: Monitor Rides -> GET /api/admin/rides
app.get('/api/admin/rides', verifyToken, requireAdmin, async (req, res) => {
    try {
        const rides = await db.collection('rides').find().toArray();
        res.status(200).json(rides);
    } catch (err) {
        res.status(401).json({ error: "Unauthorized" });
    }
});

// 11. Admin: Remove Review -> DELETE /api/admin/reviews/:id
app.delete('/api/admin/reviews/:id', verifyToken, requireAdmin, async (req, res) => {
    try {
        const result = await db.collection('reviews').deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Not Found" });

        res.status(204).send(); // No Content
    } catch (err) {
        res.status(403).json({ error: "Forbidden" });
    }
});

// 12. Admin: Generate Reports -> GET /api/admin/reports
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