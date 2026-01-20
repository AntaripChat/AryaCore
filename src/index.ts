import http, { IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';
import { URL } from 'url';
import os from 'os';

// ====================== Core Types ======================
type Handler = (req: AryaCoreRequest, res: AryaCoreResponse) => void | Promise<void>;
type Middleware = (req: AryaCoreRequest, res: AryaCoreResponse, next: (err?: any) => void) => void;
type ErrorHandler = (err: any, req: AryaCoreRequest, res: AryaCoreResponse) => void;

// ====================== CORS Types ======================
interface CorsOptions {
  origin?: string | string[] | ((origin: string | undefined) => string | boolean);
  methods?: string | string[];
  allowedHeaders?: string | string[];
  exposedHeaders?: string | string[];
  credentials?: boolean;
  maxAge?: number;
  preflightContinue?: boolean;
  optionsSuccessStatus?: number;
}

// ====================== Rate Limit Types ======================
interface RateLimitOptions {
  windowMs?: number;           // Time window in milliseconds (default: 15 minutes)
  max?: number;               // Max requests per window (default: 100)
  message?: string;           // Error message when rate limit is exceeded
  statusCode?: number;        // HTTP status code when rate limit is exceeded (default: 429)
  skipSuccessfulRequests?: boolean; // Don't count successful requests (status < 400)
  skipFailedRequests?: boolean;     // Don't count failed requests (status >= 400)
  keyGenerator?: (req: AryaCoreRequest) => string; // Function to generate keys
  skip?: (req: AryaCoreRequest) => boolean; // Function to skip rate limiting
  onLimitReached?: (req: AryaCoreRequest) => void; // Callback when limit is reached
  store?: RateLimitStore;     // Custom store implementation
}

interface RateLimitInfo {
  totalHits: number;
  resetTime: Date;
  remainingHits: number;
}

interface RateLimitStore {
  incr(key: string, windowMs: number, max: number): Promise<RateLimitInfo>;
  decrement(key: string): Promise<void>;
  resetKey(key: string): Promise<void>;
  resetAll(): Promise<void>;
}

// ====================== Route Types ======================
interface Route {
  method: string;
  path: string;
  regex: RegExp;
  keys: string[];
  handler: Handler;
}

interface AryaCoreRequest extends IncomingMessage {
  params?: Record<string, string>;
  query?: Record<string, string>;
  body?: any;
  ip?: string;
  rateLimit?: RateLimitInfo;
}

interface AryaCoreResponse extends ServerResponse {
  send: (body: any) => AryaCoreResponse;
  status: (code: number) => AryaCoreResponse;
  json: (body: object) => AryaCoreResponse;
  set: (key: string, value: string) => AryaCoreResponse;
}

interface AryaCore {
  use(middleware: Middleware): AryaCore;
  use(path: string, middleware: Middleware): AryaCore;
  get(path: string, handler: Handler): AryaCore;
  post(path: string, handler: Handler): AryaCore;
  put(path: string, handler: Handler): AryaCore;
  delete(path: string, handler: Handler): AryaCore;
  patch(path: string, handler: Handler): AryaCore;
  options(path: string, handler: Handler): AryaCore;
  onError(handler: ErrorHandler): void;
  listen(port: number, callback?: () => void): http.Server;
}

// ====================== In-Memory Store for Rate Limiting ======================
class MemoryStore implements RateLimitStore {
  private hits: Map<string, { count: number; resetTime: number }> = new Map();
  private resetTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  async incr(key: string, windowMs: number, max: number): Promise<RateLimitInfo> {
    const now = Date.now();
    let entry = this.hits.get(key);
    
    if (!entry || now > entry.resetTime) {
      // Clear existing timer
      const existingTimer = this.resetTimers.get(key);
      if (existingTimer) {
        clearTimeout(existingTimer);
      }
      
      // Create new entry
      entry = {
        count: 0,
        resetTime: now + windowMs
      };
      
      // Set timer to reset this key
      const timer = setTimeout(() => {
        this.hits.delete(key);
        this.resetTimers.delete(key);
      }, windowMs);
      
      this.resetTimers.set(key, timer);
      this.hits.set(key, entry);
    }
    
    entry.count++;
    
    return {
      totalHits: entry.count,
      resetTime: new Date(entry.resetTime),
      remainingHits: Math.max(0, max - entry.count)
    };
  }

  async decrement(key: string): Promise<void> {
    const entry = this.hits.get(key);
    if (entry && entry.count > 0) {
      entry.count--;
    }
  }

  async resetKey(key: string): Promise<void> {
    this.hits.delete(key);
    const timer = this.resetTimers.get(key);
    if (timer) {
      clearTimeout(timer);
      this.resetTimers.delete(key);
    }
  }

  async resetAll(): Promise<void> {
    for (const timer of this.resetTimers.values()) {
      clearTimeout(timer);
    }
    this.hits.clear();
    this.resetTimers.clear();
  }
}

// ====================== Rate Limiting Middleware ======================
export function rateLimit(options?: RateLimitOptions): Middleware {
  const opts: Required<Omit<RateLimitOptions, 'store' | 'keyGenerator' | 'skip' | 'onLimitReached'>> & {
    store: RateLimitStore;
    keyGenerator: (req: AryaCoreRequest) => string;
    skip?: (req: AryaCoreRequest) => boolean;
    onLimitReached?: (req: AryaCoreRequest) => void;
  } = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests, please try again later.',
    statusCode: 429,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
    store: new MemoryStore(),
    keyGenerator: (req) => {
      // Get IP address from request
      let ip = req.ip;
      if (!ip) {
        const forwarded = req.headers['x-forwarded-for'];
        ip = Array.isArray(forwarded) 
          ? forwarded[0] 
          : (forwarded || req.socket?.remoteAddress || 'unknown');
      }
      return ip as string;
    },
    ...options
  };

  return async (req, res, next) => {
    try {
      // Check if should skip rate limiting
      if (opts.skip && opts.skip(req)) {
        return next();
      }

      // Generate key for this request
      const key = opts.keyGenerator(req);
      
      // Increment counter
      const rateLimitInfo = await opts.store.incr(key, opts.windowMs, opts.max);
      req.rateLimit = rateLimitInfo;

      // Set rate limit headers
      (res as ServerResponse).setHeader('X-RateLimit-Limit', opts.max.toString());
      (res as ServerResponse).setHeader('X-RateLimit-Remaining', Math.max(0, opts.max - rateLimitInfo.totalHits).toString());
      (res as ServerResponse).setHeader('X-RateLimit-Reset', Math.ceil(rateLimitInfo.resetTime.getTime() / 1000).toString());

      // Check if rate limit exceeded
      if (rateLimitInfo.totalHits > opts.max) {
        // Call limit reached callback if provided
        if (opts.onLimitReached) {
          opts.onLimitReached(req);
        }
        
        // Set Retry-After header
        const retryAfter = Math.ceil((rateLimitInfo.resetTime.getTime() - Date.now()) / 1000);
        if (retryAfter > 0) {
          (res as ServerResponse).setHeader('Retry-After', retryAfter.toString());
        }
        
        return (res as AryaCoreResponse).status(opts.statusCode).send(opts.message);
      }

      // Store reference to original end method
      const originalEnd = (res as ServerResponse).end.bind(res);
      
      // Override end method to check response status
      (res as ServerResponse).end = function(...args: any[]): ServerResponse {
        // Call original end method
        const result = originalEnd(...args);
        
        // Handle successful/failed request counting
        if (opts.skipSuccessfulRequests || opts.skipFailedRequests) {
          const status = (res as ServerResponse).statusCode;
          const isSuccessful = status < 400;
          const isFailed = status >= 400;
          
          if ((opts.skipSuccessfulRequests && isSuccessful) || 
              (opts.skipFailedRequests && isFailed)) {
            // Decrement counter since we shouldn't count this request
            opts.store.decrement(key).catch(console.error);
          }
        }
        
        return result;
      } as any;

      next();
    } catch (error) {
      console.error('Rate limit error:', error);
      // On store error, allow the request
      next();
    }
  };
}

// ====================== CORS Middleware ======================
export function cors(options?: CorsOptions): Middleware {
  const defaultOptions: CorsOptions = {
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204,
  };

  const opts = { ...defaultOptions, ...options };

  return (req, res, next) => {
    const origin = req.headers.origin;

    // Handle origin
    if (opts.origin) {
      if (typeof opts.origin === 'function') {
        const result = opts.origin(origin);
        if (typeof result === 'string') {
          (res as ServerResponse).setHeader('Access-Control-Allow-Origin', result);
        } else if (result === true) {
          (res as ServerResponse).setHeader('Access-Control-Allow-Origin', origin || '*');
        }
      } else if (Array.isArray(opts.origin)) {
        if (origin && opts.origin.includes(origin)) {
          (res as ServerResponse).setHeader('Access-Control-Allow-Origin', origin);
        }
      } else {
        (res as ServerResponse).setHeader('Access-Control-Allow-Origin', opts.origin);
      }
    }

    // Handle credentials
    if (opts.credentials) {
      (res as ServerResponse).setHeader('Access-Control-Allow-Credentials', 'true');
    }

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      // Handle methods
      if (opts.methods) {
        const methods = Array.isArray(opts.methods) 
          ? opts.methods.join(', ') 
          : opts.methods;
        (res as ServerResponse).setHeader('Access-Control-Allow-Methods', methods);
      }

      // Handle allowed headers
      if (opts.allowedHeaders) {
        const allowedHeaders = Array.isArray(opts.allowedHeaders)
          ? opts.allowedHeaders.join(', ')
          : opts.allowedHeaders;
        (res as ServerResponse).setHeader('Access-Control-Allow-Headers', allowedHeaders);
      } else if (req.headers['access-control-request-headers']) {
        (res as ServerResponse).setHeader(
          'Access-Control-Allow-Headers',
          req.headers['access-control-request-headers'] as string
        );
      }

      // Handle max age
      if (opts.maxAge) {
        (res as ServerResponse).setHeader('Access-Control-Max-Age', String(opts.maxAge));
      }

      // Handle exposed headers
      if (opts.exposedHeaders) {
        const exposedHeaders = Array.isArray(opts.exposedHeaders)
          ? opts.exposedHeaders.join(', ')
          : opts.exposedHeaders;
        (res as ServerResponse).setHeader('Access-Control-Expose-Headers', exposedHeaders);
      }

      // Handle preflight continuation
      if (opts.preflightContinue) {
        next();
        return;
      }

      // End preflight request
      (res as ServerResponse).statusCode = opts.optionsSuccessStatus || 204;
      (res as ServerResponse).setHeader('Content-Length', '0');
      (res as ServerResponse).end();
      return;
    }

    next();
  };
}

// ====================== Router Implementation ======================
class Router {
  private routes: Route[] = [];

  addRoute(method: string, path: string, handler: Handler) {
    const { regex, keys } = this.compilePath(path);
    this.routes.push({ method, path, regex, keys, handler });
  }

  match(req: AryaCoreRequest): { handler: Handler; params: Record<string, string> } | null {
    const method = req.method || 'GET';
    const url = req.url?.split('?')[0] || '/';

    for (const route of this.routes) {
      if (route.method !== method) continue;
      
      const match = url.match(route.regex);
      if (!match) continue;

      const params: Record<string, string> = {};
      for (let i = 0; i < route.keys.length; i++) {
        params[route.keys[i]] = match[i + 1];
      }

      return { handler: route.handler, params };
    }
    return null;
  }

  private compilePath(path: string): { regex: RegExp; keys: string[] } {
    const keys: string[] = [];
    const pattern = path
      .replace(/\//g, '\\/')
      .replace(/:(\w+)/g, (_, key) => {
        keys.push(key);
        return '([^\\/]+)';
      });
    
    return {
      regex: new RegExp(`^${pattern}$`),
      keys
    };
  }
}

// ====================== Main AryaCore Implementation ======================
class AryaCoreImpl extends EventEmitter implements AryaCore {
  private router = new Router();
  private middlewares: { path?: string; handler: Middleware }[] = [];
  private errorHandler: ErrorHandler;

  constructor() {
    super();
    this.errorHandler = (err, _req, res) => {
      res.status(500).send(`Internal Server Error: ${err.message}`);
    };
  }

  use(middleware: Middleware): AryaCore;
  use(path: string, middleware: Middleware): AryaCore;
  use(arg1: string | Middleware, arg2?: Middleware): AryaCore {
    if (typeof arg1 === 'string' && arg2) {
      this.middlewares.push({ path: arg1, handler: arg2 });
    } else if (typeof arg1 === 'function') {
      this.middlewares.push({ handler: arg1 });
    }
    return this;
  }

  get(path: string, handler: Handler) {
    this.router.addRoute('GET', path, handler);
    return this;
  }

  post(path: string, handler: Handler) {
    this.router.addRoute('POST', path, handler);
    return this;
  }

  put(path: string, handler: Handler) {
    this.router.addRoute('PUT', path, handler);
    return this;
  }

  delete(path: string, handler: Handler) {
    this.router.addRoute('DELETE', path, handler);
    return this;
  }

  patch(path: string, handler: Handler) {
    this.router.addRoute('PATCH', path, handler);
    return this;
  }

  options(path: string, handler: Handler) {
    this.router.addRoute('OPTIONS', path, handler);
    return this;
  }

  onError(handler: ErrorHandler) {
    this.errorHandler = handler;
  }

  private activeServer: http.Server | null = null;

  private enhanceResponse(res: ServerResponse): AryaCoreResponse {
    const enhancedRes = res as AryaCoreResponse;
    
    enhancedRes.send = (body: any) => {
      if (typeof body === 'object') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(body));
      } else {
        res.setHeader('Content-Type', 'text/plain');
        res.end(body);
      }
      return enhancedRes;
    };
    
    enhancedRes.json = (body: object) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(body));
      return enhancedRes;
    };
    
    enhancedRes.status = (code: number) => {
      res.statusCode = code;
      return enhancedRes;
    };
    
    enhancedRes.set = (key: string, value: string) => {
      res.setHeader(key, value);
      return enhancedRes;
    };
    
    return enhancedRes;
  }

  private parseQuery(url: string): Record<string, string> {
    const query: Record<string, string> = {};
    try {
      const queryString = new URL(url, 'http://localhost').searchParams;
      queryString.forEach((value: string, key: string) => {
        query[key] = value;
      });
    } catch (e) {
      const queryString = url.split('?')[1];
      if (queryString) {
        queryString.split('&').forEach(pair => {
          const [key, value] = pair.split('=');
          if (key) query[decodeURIComponent(key)] = decodeURIComponent(value || '');
        });
      }
    }
    return query;
  }

  private parseRequestBody(req: AryaCoreRequest): Promise<void> {
    return new Promise((resolve, reject) => {
      if (req.method === 'GET' || req.method === 'HEAD') {
        return resolve();
      }
      
      let body = '';
      req.on('data', (chunk: Buffer) => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        try {
          const contentType = req.headers['content-type'] || '';
          
          if (contentType.includes('application/json') && body) {
            req.body = JSON.parse(body);
          } 
          else if (contentType.includes('application/x-www-form-urlencoded') && body) {
            const params = new URLSearchParams(body);
            req.body = Object.fromEntries(params);
          }
          else if (body) {
            req.body = body;
          }
          resolve();
        } catch (e) {
          reject(e);
        }
      });
      
      req.on('error', (err: Error) => {
        reject(err);
      });
    });
  }

  private async processRequest(req: AryaCoreRequest, res: AryaCoreResponse) {
    try {
      // Store IP address in request object for rate limiting
      const forwarded = req.headers['x-forwarded-for'];
      req.ip = Array.isArray(forwarded) 
        ? forwarded[0] 
        : (forwarded || req.socket?.remoteAddress || 'unknown');

      // Parse query parameters
      req.query = this.parseQuery(req.url || '/');
      
      // Parse request body for POST, PUT, PATCH requests
      if (['POST', 'PUT', 'PATCH'].includes(req.method || '')) {
        await this.parseRequestBody(req);
      }
      
      // Process global middlewares
      for (const { handler } of this.middlewares.filter(m => !m.path)) {
        await this.runMiddleware(handler, req, res);
        if ((res as ServerResponse).writableEnded) return;
      }
      
      // Process path-specific middlewares
      const urlPath = req.url?.split('?')[0] || '/';
      for (const { path, handler } of this.middlewares.filter(m => m.path)) {
        if (!path || urlPath.startsWith(path)) {
          await this.runMiddleware(handler, req, res);
          if ((res as ServerResponse).writableEnded) return;
        }
      }
      
      // Find matching route
      const route = this.router.match(req);
      if (route) {
        req.params = route.params;
        await this.runHandler(route.handler, req, res);
      } else {
        res.status(404).send('Not Found');
      }
    } catch (err) {
      this.errorHandler(err, req, res);
    }
  }

  private runMiddleware(
    middleware: Middleware, 
    req: AryaCoreRequest, 
    res: AryaCoreResponse
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const next = (err?: any) => {
        if (err) reject(err);
        else resolve();
      };
      
      try {
        middleware(req, res, next);
      } catch (err) {
        reject(err);
      }
    });
  }

  private async runHandler(
    handler: Handler, 
    req: AryaCoreRequest, 
    res: AryaCoreResponse
  ) {
    const result = handler(req, res);
    if (result instanceof Promise) {
      await result;
    }
  }

  listen(port: number, callback?: () => void): http.Server {
    this.activeServer = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const enhancedReq = req as AryaCoreRequest;
      const enhancedRes = this.enhanceResponse(res);
      
      await this.processRequest(enhancedReq, enhancedRes);
    });

    return this.activeServer.listen(port, () => {
      // Create the stylish ASCII banner
      const banner = `
    █████╗ ██████╗ ██╗   ██╗ █████╗      ██████╗ ██████╗ ██████╗ ███████╗
   ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗██╔════╝
   ███████║██████╔╝ ╚████╔╝ ███████║    ██║     ██║   ██║██████╔╝█████╗  
   ██╔══██║██╔══██╗  ╚██╔╝  ██╔══██║    ██║     ██║   ██║██╔══██╗██╔══╝  
   ██║  ██║██║  ██║   ██║   ██║  ██║    ╚██████╗╚██████╔╝██║  ██║███████╗
   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
      `;

      console.log(`\x1b[36m${banner}\x1b[0m`);  // Cyan color
      console.log(`\x1b[32m🚀 Server successfully started on port \x1b[33m${port}\x1b[0m`);
      console.log(`\x1b[90m➜ Local:   \x1b[0m\x1b[36mhttp://localhost:${port}/\x1b[0m`);
      console.log(`\x1b[90m➜ Network: \x1b[0m\x1b[36mhttp://${getIPAddress()}:${port}/\x1b[0m`);

      if (callback) {
        callback();
      }
    });
  }
}

// Helper function to get IP address
function getIPAddress(): string {
  const interfaces = os.networkInterfaces();
  for (const devName in interfaces) {
    const iface = interfaces[devName];
    if (!iface) continue;
    for (let i = 0; i < iface.length; i++) {
      const alias = iface[i];
      if (alias.family === 'IPv4' && 
          alias.address !== '127.0.0.1' && 
          !alias.internal) {
        return alias.address;
      }
    }
  }
  return 'localhost';
}

// Public API
export function createApp(): AryaCore {
  return new AryaCoreImpl();
}

// CommonJS Export
const createAppCJS = createApp;
export default createAppCJS;

// For CommonJS environment
if (typeof module !== 'undefined' && module.exports) {
  module.exports = createAppCJS;
  module.exports.createApp = createApp;
  module.exports.cors = cors;
  module.exports.rateLimit = rateLimit;
  module.exports.AryaCore = AryaCoreImpl;
  module.exports.MemoryStore = MemoryStore;
}