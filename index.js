require('dotenv').config();  // Load .env variables

const express = require('express');
const authRoutes = require('./routes/auth.routes');

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Fix: Use Express's built-in JSON parser
app.use(express.json());

// ✅ Route for OTP APIs
app.use('/auth', authRoutes);

// ✅ Test route
app.get('/', (req, res) => res.send('FlexMitra API is working 🚀'));

// ✅ Start the server
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
