const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Import Models
const User = require('./models/User');
const Product = require('./models/Product');
const Order = require('./models/Order');

const app = express();
app.use(express.json());
app.use(cors());

// Database Connection
let isConnected = false;
const connectDB = async () => {
    if (isConnected) return;
    await mongoose.connect(process.env.MONGODB_URI);
    isConnected = true;
};

// --- AUTH ROUTES ---

// Register
app.post('/api/auth/register', async (req, res) => {
    await connectDB();
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, email, password: hashedPassword });
        res.json({ message: "User created" });
    } catch (e) { res.status(400).json({ error: "Email already exists" }); }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    await connectDB();
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET || 'secret', { expiresIn: '1d' });
    res.json({ token, isAdmin: user.isAdmin, username: user.username });
});

// --- PRODUCT ROUTES ---

app.get('/api/products', async (req, res) => {
    await connectDB();
    const products = await Product.find({});
    res.json(products);
});

// Admin Add Product
app.post('/api/products', async (req, res) => {
    await connectDB();
    // In real app, verify admin token here
    const product = await Product.create(req.body);
    res.json(product);
});

// --- ORDER ROUTES ---

app.post('/api/orders', async (req, res) => {
    await connectDB();
    const { token, cart } = req.body;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const total = cart.reduce((acc, item) => acc + item.price, 0);
        
        const order = await Order.create({
            userId: decoded.id,
            products: cart,
            total: total
        });
        res.json({ success: true, orderId: order._id });
    } catch (e) { res.status(401).json({ error: "Unauthorized" }); }
});

app.get('/api/orders/my', async (req, res) => {
    await connectDB();
    const token = req.headers.authorization?.split(' ')[1];
    if(!token) return res.status(401).json([]);
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const orders = await Order.find({ userId: decoded.id }).sort({ date: -1 });
        res.json(orders);
    } catch(e) { res.status(401).json([]); }
});

// Export for Vercel
module.exports = app;
