# AryaCore

**AryaCore** is a lightweight, high-performance Node.js web framework built on top of the native `http` module. Inspired by Express and Fastify, it provides essential web framework features with minimal overhead.

![AryaCore Banner](https://img.shields.io/npm/v/aryacore?style=for-the-badge)
![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue?style=for-the-badge)
![MIT License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=for-the-badge)

## 🚀 Features

- ⚡ **Blazing fast** - Built directly on Node.js http module
- 🛣️ **Flexible routing** - Supports all HTTP methods with path parameters
- 🔌 **Middleware system** - Chainable middleware support
- 🛡️ **Built-in CORS** - Easy CORS configuration
- ⏱️ **Rate Limiting** - Protect your API from abuse
- 🔧 **TypeScript ready** - Full TypeScript support
- 📦 **Zero dependencies** - Minimal footprint
- 🎯 **Error handling** - Custom error handling support

## 📦 Installation

```bash
npm install aryacore
# or
yarn add aryacore
```

## 📚 Quick Start

### Basic Server

```javascript
const { createApp } = require('aryacore');
const app = createApp();

// Simple route
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// Start server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### TypeScript Usage

```typescript
import { createApp } from 'aryacore';

const app = createApp();

app.get('/', (req, res) => {
  res.json({ message: 'Hello from TypeScript!' });
});

app.listen(3000);
```

## 📖 API Reference

### Routing Methods

AryaCore supports all standard HTTP methods:

```javascript
app.get('/path', handler)
app.post('/path', handler)
app.put('/path', handler)
app.delete('/path', handler)
app.patch('/path', handler)
app.options('/path', handler)
```

### Route Parameters

```javascript
app.get('/users/:id', (req, res) => {
  res.json({
    userId: req.params.id,  // Access route parameters
    query: req.query        // Access query parameters
  });
});
```

### Query Parameters

```javascript
// GET /search?q=arya&page=2
app.get('/search', (req, res) => {
  const { q, page = '1' } = req.query;
  res.json({ search: q, page: parseInt(page) });
});
```

### Request Body

```javascript
app.post('/users', (req, res) => {
  const userData = req.body;
  // req.body is automatically parsed for JSON and form-encoded data
  res.json({ success: true, data: userData });
});
```

### Middleware

#### Global Middleware

```javascript
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  console.log('User IP:', req.ip);
  next(); // Don't forget to call next()!
});
```

#### Path-Specific Middleware

```javascript
app.use('/admin', (req, res, next) => {
  // This will run for all routes starting with /admin
  if (!req.headers['x-auth-token']) {
    return res.status(401).send('Unauthorized');
  }
  next();
});

app.get('/admin/dashboard', (req, res) => {
  res.send('Admin Dashboard');
});
```

### Response Methods

```javascript
app.get('/response-test', (req, res) => {
  // Set status code
  res.status(201);
  
  // Set headers
  res.set('X-Custom-Header', 'value');
  
  // Send text response
  res.send('Hello World');
  
  // Or send JSON
  res.json({ message: 'Hello JSON' });
});

// Method chaining
app.get('/chain', (req, res) => {
  res
    .status(200)
    .set('Content-Type', 'application/json')
    .json({ message: 'Chained methods' });
});
```

### Error Handling

```javascript
// Global error handler
app.onError((err, req, res) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// Throwing errors in routes
app.get('/error', (req, res) => {
  throw new Error('Something went wrong!');
});

// Async error handling
app.get('/async-error', async (req, res) => {
  await someAsyncOperation();
  // Errors in async functions are automatically caught
});
```

## 🔧 Built-in Middleware

### CORS Middleware

```javascript
const { cors } = require('aryacore');

// Basic CORS (allow all origins)
app.use(cors());

// Configured CORS
app.use(cors({
  origin: 'https://yourdomain.com',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

// Multiple origins
app.use(cors({
  origin: ['https://domain1.com', 'https://domain2.com']
}));

// Dynamic origin
app.use(cors({
  origin: (origin) => {
    const allowedOrigins = ['https://domain1.com', 'https://domain2.com'];
    return allowedOrigins.includes(origin) ? origin : false;
  }
}));
```

### Rate Limiting

```javascript
const { rateLimit } = require('aryacore');

// Global rate limiting (100 requests per 15 minutes)
app.use(rateLimit());

// Custom rate limiting
app.use(rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute
  message: 'Too many requests, please try again later.',
  statusCode: 429,
  skip: (req) => {
    // Skip rate limiting for certain paths
    return req.url?.startsWith('/public/') || false;
  },
  onLimitReached: (req) => {
    console.log(`Rate limit reached for IP: ${req.ip}`);
  }
}));

// Route-specific rate limiting
const strictRateLimit = rateLimit({
  windowMs: 30 * 1000, // 30 seconds
  max: 3, // Only 3 requests per 30 seconds
  message: 'Please slow down!'
});

app.get('/api/sensitive', (req, res, next) => {
  strictRateLimit(req, res, () => {
    // Access rate limit info
    console.log(req.rateLimit);
    res.json({ sensitive: 'data' });
  });
});
```

## 🧩 Advanced Examples

### RESTful API with In-Memory Database

```javascript
const { createApp } = require('aryacore');
const app = createApp();

const todos = new Map();
let nextId = 1;

// GET all todos
app.get('/todos', (req, res) => {
  const allTodos = Array.from(todos.values());
  res.json(allTodos);
});

// GET single todo
app.get('/todos/:id', (req, res) => {
  const todo = todos.get(req.params.id);
  if (!todo) {
    return res.status(404).json({ error: 'Todo not found' });
  }
  res.json(todo);
});

// POST create todo
app.post('/todos', (req, res) => {
  const id = (nextId++).toString();
  const todo = {
    id,
    ...req.body,
    createdAt: new Date().toISOString()
  };
  todos.set(id, todo);
  res.status(201).json(todo);
});

// PUT update todo
app.put('/todos/:id', (req, res) => {
  if (!todos.has(req.params.id)) {
    return res.status(404).json({ error: 'Todo not found' });
  }
  const updatedTodo = {
    ...todos.get(req.params.id),
    ...req.body,
    updatedAt: new Date().toISOString()
  };
  todos.set(req.params.id, updatedTodo);
  res.json(updatedTodo);
});

// DELETE todo
app.delete('/todos/:id', (req, res) => {
  if (!todos.has(req.params.id)) {
    return res.status(404).json({ error: 'Todo not found' });
  }
  todos.delete(req.params.id);
  res.status(204).send();
});

app.listen(3000);
```

### Authentication Middleware

```javascript
const { createApp } = require('aryacore');
const app = createApp();

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  // In a real app, verify JWT or check database
  if (token !== 'Bearer secret-token') {
    return res.status(403).json({ error: 'Invalid token' });
  }
  
  req.user = { id: 1, name: 'John Doe' };
  next();
}

// Protected routes
app.get('/profile', authenticate, (req, res) => {
  res.json({
    message: 'Welcome to your profile',
    user: req.user
  });
});

app.get('/dashboard', authenticate, (req, res) => {
  res.json({
    message: 'Dashboard data',
    user: req.user
  });
});

// Public routes
app.get('/public', (req, res) => {
  res.json({ message: 'Public data' });
});

app.listen(3000);
```

### File Upload Handler

```javascript
const { createApp } = require('aryacore');
const fs = require('fs');
const path = require('path');
const app = createApp();

// Upload directory
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

app.post('/upload', (req, res) => {
  let data = '';
  let contentType = req.headers['content-type'] || '';
  
  req.on('data', chunk => {
    data += chunk.toString();
  });
  
  req.on('end', () => {
    try {
      if (contentType.includes('multipart/form-data')) {
        // Parse multipart form data (simplified)
        const filename = `upload-${Date.now()}.txt`;
        const filepath = path.join(UPLOAD_DIR, filename);
        fs.writeFileSync(filepath, data);
        
        res.json({
          success: true,
          filename,
          size: data.length
        });
      } else {
        res.status(400).json({ error: 'Unsupported content type' });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
});

app.listen(3000);
```

### Webhook Handler

```javascript
const { createApp } = require('aryacore');
const crypto = require('crypto');
const app = createApp();

const WEBHOOK_SECRET = 'your-webhook-secret';

// Verify webhook signature middleware
function verifyWebhook(req, res, next) {
  const signature = req.headers['x-webhook-signature'];
  const payload = JSON.stringify(req.body);
  
  const expectedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');
    
  if (signature !== expectedSignature) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  next();
}

// Webhook endpoint
app.post('/webhook', verifyWebhook, (req, res) => {
  const event = req.body;
  
  console.log('Webhook received:', event.type);
  
  // Process the webhook event
  switch (event.type) {
    case 'payment.succeeded':
      // Handle successful payment
      break;
    case 'payment.failed':
      // Handle failed payment
      break;
    default:
      // Handle other events
  }
  
  res.json({ received: true });
});

app.listen(3000);
```

## 🎯 TypeScript Examples

### Type-Safe Routes with TypeScript

```typescript
import { createApp } from 'aryacore';

interface User {
  id: string;
  name: string;
  email: string;
}

interface CreateUserDto {
  name: string;
  email: string;
  password: string;
}

const app = createApp();
const users = new Map<string, User>();

// Get user with typed params
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const user = users.get(userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json(user);
});

// Create user with typed body
app.post('/users', (req, res) => {
  const userData = req.body as CreateUserDto;
  const id = Date.now().toString();
  
  const newUser: User = {
    id,
    name: userData.name,
    email: userData.email
  };
  
  users.set(id, newUser);
  res.status(201).json(newUser);
});

// Update user
app.put('/users/:id', (req, res) => {
  const userId = req.params.id;
  const updates = req.body as Partial<User>;
  
  const existingUser = users.get(userId);
  if (!existingUser) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const updatedUser = { ...existingUser, ...updates };
  users.set(userId, updatedUser);
  res.json(updatedUser);
});

app.listen(3000);
```

### Custom Request Interface

```typescript
import { createApp, AryaCoreRequest } from 'aryacore';

// Extend the request interface
interface AuthenticatedRequest extends AryaCoreRequest {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

const app = createApp();

// Custom authentication middleware
function authMiddleware(req: AryaCoreRequest, res, next) {
  const token = req.headers['authorization'];
  
  // In a real app, verify the token
  if (token === 'Bearer valid-token') {
    (req as AuthenticatedRequest).user = {
      id: '123',
      email: 'user@example.com',
      role: 'admin'
    };
  }
  
  next();
}

// Use the middleware
app.use(authMiddleware);

app.get('/profile', (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  res.json({
    message: 'Your profile',
    user: req.user
  });
});

app.listen(3000);
```

## 📊 Performance

AryaCore is designed for performance. Here's a simple benchmark comparison:

```javascript
// Simple benchmark
const { createApp } = require('aryacore');
const autocannon = require('autocannon');

const app = createApp();

app.get('/', (req, res) => {
  res.json({ message: 'Hello World' });
});

const server = app.listen(3000);

// Run benchmark after server starts
setTimeout(() => {
  autocannon({
    url: 'http://localhost:3000',
    connections: 100,
    duration: 10
  }, (err, results) => {
    console.log('Benchmark results:', results);
    server.close();
  });
}, 1000);
```

## 🔍 Debugging

Enable debug logging:

```javascript
const app = createApp();

// Add debug middleware
app.use((req, res, next) => {
  console.log('=== Request Debug ===');
  console.log('Method:', req.method);
  console.log('URL:', req.url);
  console.log('Headers:', req.headers);
  console.log('IP:', req.ip);
  console.log('====================');
  next();
});

// ... your routes ...
```

## 🚨 Error Codes

Common HTTP status codes and their meanings:

- `200` - OK
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests (Rate Limited)
- `500` - Internal Server Error

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by Express.js and Fastify
- Built with ❤️ for the Node.js community
- Thanks to all contributors

## 🐛 Reporting Issues

If you find a bug or have a feature request, please [open an issue](https://github.com/yourusername/aryacore/issues).

---

**Made with ❤️ by the AryaCore Team**

> **Note:** This project is actively maintained. Some features may be added or changed in future releases.
```