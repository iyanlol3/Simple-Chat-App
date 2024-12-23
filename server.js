require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const session = require('express-session');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);


app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 
  }
}));


app.use(express.json());
app.use(express.static('public'));


const checkAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};


mongoose.connect('mongodb://localhost:27017/chat-app')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));


const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);


const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);


const socketRateLimit = new Map();


const socketRateLimiter = (socket, next) => {
  const clientId = socket.handshake.address;
  if (!socketRateLimit.has(clientId)) {
    socketRateLimit.set(clientId, {
      timestamp: Date.now(),
      count: 1
    });
    return next();
  }

  const rateLimitInfo = socketRateLimit.get(clientId);
  const currentTime = Date.now();
  const timeWindow = 60000; 
  const maxConnections = 100;

  if (currentTime - rateLimitInfo.timestamp > timeWindow) {
    socketRateLimit.set(clientId, {
      timestamp: currentTime,
      count: 1
    });
    return next();
  }

  if (rateLimitInfo.count >= maxConnections) {
    return next(new Error('Too many connection attempts. Please try again later.'));
  }

  rateLimitInfo.count++;
  socketRateLimit.set(clientId, rateLimitInfo);
  next();
};


io.use(socketRateLimiter);
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const userId = socket.handshake.auth.userId;

  if (!token || !userId) {
    return next(new Error('Authentication required'));
  }

  try {
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-jwt-secret');
    
    if (decoded.userId !== userId) {
      return next(new Error('Invalid authentication credentials'));
    }

    
    socket.userId = userId;
    socket.user = decoded;
    next();
  } catch (error) {
    return next(new Error('Invalid token'));
  }
});


app.get('/api/check-session', async (req, res) => {
  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId);
      if (user) {
        
        const token = jwt.sign(
          { userId: user._id, username: user.username },
          process.env.JWT_SECRET || 'your-jwt-secret',
          { expiresIn: '24h' }
        );

        res.json({ 
          isAuthenticated: true, 
          user: { 
            id: user._id,
            username: user.username 
          },
          token 
        });
        return;
      }
    } catch (error) {
      console.error('Session check error:', error);
    }
  }
  res.json({ isAuthenticated: false });
});


app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-jwt-secret',
      { expiresIn: '24h' }
    );

    
    req.session.userId = user._id;
    
    res.json({ 
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username
      },
      token 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ error: 'Could not log out' });
    } else {
      res.json({ message: 'Logged out successfully' });
    }
  });
});


io.on('connection', async (socket) => {
  console.log('User connected:', socket.user.username);

  try {
    
    const messages = await Message.find()
      .populate('sender', 'username')
      .sort({ timestamp: -1 })
      .limit(50);
    socket.emit('previous-messages', messages.reverse());

    
    socket.on('send-message', async (content) => {
      try {
        if (!content || typeof content !== 'string' || content.length > 1000) {
          throw new Error('Invalid message content');
        }

        const message = new Message({
          sender: socket.userId,
          content: content.trim()
        });
        await message.save();
        const populatedMessage = await message.populate('sender', 'username');
        io.emit('new-message', populatedMessage);
      } catch (error) {
        socket.emit('error', { message: 'Failed to send message: ' + error.message });
      }
    });

    socket.on('disconnect', () => {
      console.log('User disconnected:', socket.user.username);
    });

    
    socket.on('error', (error) => {
      console.error('Socket error:', error);
      socket.emit('error', { message: 'An error occurred' });
    });

  } catch (error) {
    console.error('Socket connection error:', error);
    socket.disconnect(true);
  }
});


app.get('/', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
