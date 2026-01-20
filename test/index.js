const { createApp, rateLimit, cors } = require('../dist');

const app = createApp();

// Apply rate limiting globally
app.use(rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute
  message: 'Too many requests from this IP, please try again after a minute.',
  statusCode: 429,
  skip: (req) => {
    // Skip rate limiting for certain paths
    return req.url?.startsWith('/public/') || false;
  },
  onLimitReached: (req) => {
    console.log(`Rate limit reached for IP: ${req.ip}`);
  }
}));

// Apply CORS
app.use(cors());

// Route with global rate limiting
app.get('/api/data', (req, res) => {
  res.json({ data: 'Some data' });
});

// For route-specific rate limiting, you need to create a route handler
// that wraps the middleware. Your framework doesn't support middleware
// as route parameters yet. Here's a workaround:

// First, create a custom middleware stack
const sensitiveRouteHandler = (req, res, next) => {
  const strictRateLimit = rateLimit({
    windowMs: 30 * 1000, // 30 seconds
    max: 3, // Only 3 requests per 30 seconds
    message: 'Please slow down!'
  });
  
  // Apply the rate limiting middleware
  strictRateLimit(req, res, () => {
    // If rate limit passes, execute the actual handler
    console.log(req.rateLimit);
    res.json({ sensitive: 'data' });
  });
};

app.get('/api/sensitive', sensitiveRouteHandler);

// Public route (should skip rate limiting based on the skip function)
app.get('/public/info', (req, res) => {
  res.json({ info: 'This is public information' });
});

// Simple test routes
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to AryaCore API' });
});

app.get('/api/user/:id', (req, res) => {
  res.json({ userId: req.params.id, name: 'John Doe' });
});

app.post('/api/user', (req, res) => {
  res.json({ message: 'User created', data: req.body });
});

// Error handling
app.onError((err, req, res) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
  console.log('Test endpoints:');
  console.log('  GET  /              - Welcome message');
  console.log('  GET  /api/data      - Global rate limit (5/min)');
  console.log('  GET  /api/sensitive - Strict rate limit (3/30s)');
  console.log('  GET  /public/info   - No rate limiting');
  console.log('  GET  /api/user/:id  - Parameter route');
  console.log('  POST /api/user      - Body parsing test');
});