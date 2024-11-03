// Required dependencies
const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => console.error("Error connecting to MongoDB:", error));


// Models
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  roomId: { type: String, required: true },
  sender: { type: String, required: true },
  content: { type: String, required: true },
  type: { type: String, enum: ['text', 'file'], default: 'text' },
  fileUrl: { type: String },
  reactions: [{ 
    user: String,
    emoji: String
  }],
  createdAt: { type: Date, default: Date.now }
});

const roomSchema = new mongoose.Schema({
  name: { type: String, required: true },
  creator: { type: String, required: true },
  isPrivate: { type: Boolean, default: false },
  members: [{ type: String }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Room = mongoose.model('Room', roomSchema);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Rate limiting
const messageLimiter = rateLimit({
  windowMs: 10 * 1000, // 10 seconds
  max: 5 // 5 messages per window
});

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      password: hashedPassword
    });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error creating user' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Error logging in' });
  }
});

// Room routes
app.post('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const room = new Room({
      name: req.body.name,
      creator: req.user.username,
      isPrivate: req.body.isPrivate,
      members: [req.user.username]
    });
    await room.save();
    res.status(201).json(room);
  } catch (error) {
    res.status(500).json({ error: 'Error creating room' });
  }
});

app.get('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const rooms = await Room.find({ 
      $or: [
        { isPrivate: false },
        { members: req.user.username }
      ]
    });
    res.json(rooms);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching rooms' });
  }
});

// Socket.IO handling
const activeUsers = new Map(); // Store active users by socket ID
const typingUsers = new Map(); // Store typing status

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.user.username);
  activeUsers.set(socket.id, socket.user.username);

  // Join room
  socket.on('join room', async (roomId) => {
    socket.join(roomId);
    
    // Fetch last 20 messages
    const messages = await Message.find({ roomId })
      .sort({ createdAt: -1 })
      .limit(20);
    
    socket.emit('message history', messages.reverse());
    io.to(roomId).emit('user joined', socket.user.username);
    io.to(roomId).emit('active users', Array.from(activeUsers.values()));
  });

  // Handle new message
  socket.on('new message', async (data) => {
    try {
      const message = new Message({
        roomId: data.roomId,
        sender: socket.user.username,
        content: data.content,
        type: data.type,
        fileUrl: data.fileUrl
      });
      await message.save();
      io.to(data.roomId).emit('message', message);
    } catch (error) {
      socket.emit('error', 'Error sending message');
    }
  });

  // Handle typing indicator
  socket.on('typing', (roomId) => {
    typingUsers.set(socket.id, roomId);
    io.to(roomId).emit('user typing', socket.user.username);
  });

  socket.on('stop typing', (roomId) => {
    typingUsers.delete(socket.id);
    io.to(roomId).emit('user stopped typing', socket.user.username);
  });

  // Handle private messages
  socket.on('private message', async (data) => {
    const recipientSocket = Array.from(activeUsers.entries())
      .find(([_, username]) => username === data.recipient)?.[0];
    
    if (recipientSocket) {
      io.to(recipientSocket).emit('private message', {
        sender: socket.user.username,
        content: data.content
      });
    }
  });

  // Handle message reactions
  socket.on('add reaction', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      message.reactions.push({
        user: socket.user.username,
        emoji: data.emoji
      });
      await message.save();
      io.to(data.roomId).emit('message reaction', {
        messageId: data.messageId,
        reaction: {
          user: socket.user.username,
          emoji: data.emoji
        }
      });
    } catch (error) {
      socket.emit('error', 'Error adding reaction');
    }
  });

  // Handle disconnect
  socket.on('disconnect', () => {
    const rooms = Array.from(socket.rooms);
    rooms.forEach(room => {
      io.to(room).emit('user left', socket.user.username);
    });
    activeUsers.delete(socket.id);
    typingUsers.delete(socket.id);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});