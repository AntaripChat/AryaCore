# AryaCore

**AryaCore** is a lightweight, high-performance Node.js web framework built on top of the native `http` module. Inspired by Express and Fastify, it provides essential web framework features with minimal overhead.

## 🚀 Features

- ⚡ **Blazing fast** - Built directly on Node.js http module
- 🛣️ **Flexible routing** - Supports all HTTP methods with path parameters
- 🔌 **Middleware system** - Chainable middleware support
- 🛡️ **Error handling** - Custom error handling support
- 📦 **Zero dependencies** - Minimal footprint
- 💪 **TypeScript ready** - Built with TypeScript

## 📦 Installation

```bash
npm install aryacore
# or
yarn add aryacore
```

# Basic Usage

``` javascript

const { createApp } = require('aryacore');
const app = createApp();

// Simple route
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.post('/', (req, res) => {
  const data = req.body;
 res.send(data.data);
});

// Start server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});

```

📚 API Reference

**Routing**

AryaCore supports all standard HTTP methods:

``` javascript

app.get('/path', handler)
app.post('/path', handler)
app.put('/path', handler)
app.delete('/path', handler)
app.patch('/path', handler)
app.options('/path', handler)

```

**Route Parameters**


``` javascript
app.get('/users/:id', (req, res) => {
  res.json({
    userId: req.params.id,  // Access route parameters
    query: req.query       // Access query parameters
  });
});

```

**Middleware**

Global middleware:

``` javascript
app.use((req, res, next) => {
  console.log('Request received');
  next(); // Don't forget to call next()!
});

```
Path-specific middleware:

``` javascript
app.use('/admin', (req, res, next) => {
  // This will run for all routes starting with /admin
  if (!req.headers['x-auth-token']) {
    return res.status(401).send('Unauthorized');
  }
  next();
});
```
**Error Handling**

``` javascript
app.onError((err, req, res) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong!' });
});

```
**Response Methods**

    res.status(code) - Set status code

    res.send(body) - Send response (auto-detects content type)

    res.json(body) - Send JSON response

    res.set(key, value) - Set header

**🧩 Advanced Examples**
JSON API Example

``` javascript
const app = createApp();

// Middleware to parse JSON
app.use(async (req, res, next) => {
  if (req.headers['content-type'] === 'application/json') {
    await new Promise((resolve) => {
      let data = '';
      req.on('data', chunk => data += chunk);
      req.on('end', () => {
        try {
          req.body = JSON.parse(data);
          next();
        } catch (e) {
          res.status(400).send('Invalid JSON');
        }
      });
    });
  } else {
    next();
  }
});

app.post('/api/data', (req, res) => {
  res.json({ received: req.body });
});

app.listen(3000);
```
**RESTful Resource**

``` javascript
const db = new Map(); // Simple in-memory "database"

app.post('/todos', (req, res) => {
  const id = Date.now().toString();
  db.set(id, req.body);
  res.status(201).json({ id, ...req.body });
});

app.get('/todos/:id', (req, res) => {
  const todo = db.get(req.params.id);
  if (!todo) return res.status(404).send('Not found');
  res.json(todo);
});
```

> **Note:** This project is under development, so some features may not work as expected.
