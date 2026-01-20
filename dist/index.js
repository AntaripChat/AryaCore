"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rateLimit = rateLimit;
exports.cors = cors;
exports.createApp = createApp;
const http_1 = __importDefault(require("http"));
const events_1 = require("events");
const url_1 = require("url");
const os_1 = __importDefault(require("os"));
// ====================== In-Memory Store for Rate Limiting ======================
class MemoryStore {
    constructor() {
        this.hits = new Map();
        this.resetTimers = new Map();
    }
    async incr(key, windowMs, max) {
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
    async decrement(key) {
        const entry = this.hits.get(key);
        if (entry && entry.count > 0) {
            entry.count--;
        }
    }
    async resetKey(key) {
        this.hits.delete(key);
        const timer = this.resetTimers.get(key);
        if (timer) {
            clearTimeout(timer);
            this.resetTimers.delete(key);
        }
    }
    async resetAll() {
        for (const timer of this.resetTimers.values()) {
            clearTimeout(timer);
        }
        this.hits.clear();
        this.resetTimers.clear();
    }
}
// ====================== Rate Limiting Middleware ======================
function rateLimit(options) {
    const opts = {
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
            return ip;
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
            res.setHeader('X-RateLimit-Limit', opts.max.toString());
            res.setHeader('X-RateLimit-Remaining', Math.max(0, opts.max - rateLimitInfo.totalHits).toString());
            res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimitInfo.resetTime.getTime() / 1000).toString());
            // Check if rate limit exceeded
            if (rateLimitInfo.totalHits > opts.max) {
                // Call limit reached callback if provided
                if (opts.onLimitReached) {
                    opts.onLimitReached(req);
                }
                // Set Retry-After header
                const retryAfter = Math.ceil((rateLimitInfo.resetTime.getTime() - Date.now()) / 1000);
                if (retryAfter > 0) {
                    res.setHeader('Retry-After', retryAfter.toString());
                }
                return res.status(opts.statusCode).send(opts.message);
            }
            // Store reference to original end method
            const originalEnd = res.end.bind(res);
            // Override end method to check response status
            res.end = function (...args) {
                // Call original end method
                const result = originalEnd(...args);
                // Handle successful/failed request counting
                if (opts.skipSuccessfulRequests || opts.skipFailedRequests) {
                    const status = res.statusCode;
                    const isSuccessful = status < 400;
                    const isFailed = status >= 400;
                    if ((opts.skipSuccessfulRequests && isSuccessful) ||
                        (opts.skipFailedRequests && isFailed)) {
                        // Decrement counter since we shouldn't count this request
                        opts.store.decrement(key).catch(console.error);
                    }
                }
                return result;
            };
            next();
        }
        catch (error) {
            console.error('Rate limit error:', error);
            // On store error, allow the request
            next();
        }
    };
}
// ====================== CORS Middleware ======================
function cors(options) {
    const defaultOptions = {
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
                    res.setHeader('Access-Control-Allow-Origin', result);
                }
                else if (result === true) {
                    res.setHeader('Access-Control-Allow-Origin', origin || '*');
                }
            }
            else if (Array.isArray(opts.origin)) {
                if (origin && opts.origin.includes(origin)) {
                    res.setHeader('Access-Control-Allow-Origin', origin);
                }
            }
            else {
                res.setHeader('Access-Control-Allow-Origin', opts.origin);
            }
        }
        // Handle credentials
        if (opts.credentials) {
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        // Handle preflight requests
        if (req.method === 'OPTIONS') {
            // Handle methods
            if (opts.methods) {
                const methods = Array.isArray(opts.methods)
                    ? opts.methods.join(', ')
                    : opts.methods;
                res.setHeader('Access-Control-Allow-Methods', methods);
            }
            // Handle allowed headers
            if (opts.allowedHeaders) {
                const allowedHeaders = Array.isArray(opts.allowedHeaders)
                    ? opts.allowedHeaders.join(', ')
                    : opts.allowedHeaders;
                res.setHeader('Access-Control-Allow-Headers', allowedHeaders);
            }
            else if (req.headers['access-control-request-headers']) {
                res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers']);
            }
            // Handle max age
            if (opts.maxAge) {
                res.setHeader('Access-Control-Max-Age', String(opts.maxAge));
            }
            // Handle exposed headers
            if (opts.exposedHeaders) {
                const exposedHeaders = Array.isArray(opts.exposedHeaders)
                    ? opts.exposedHeaders.join(', ')
                    : opts.exposedHeaders;
                res.setHeader('Access-Control-Expose-Headers', exposedHeaders);
            }
            // Handle preflight continuation
            if (opts.preflightContinue) {
                next();
                return;
            }
            // End preflight request
            res.statusCode = opts.optionsSuccessStatus || 204;
            res.setHeader('Content-Length', '0');
            res.end();
            return;
        }
        next();
    };
}
// ====================== Router Implementation ======================
class Router {
    constructor() {
        this.routes = [];
    }
    addRoute(method, path, handler) {
        const { regex, keys } = this.compilePath(path);
        this.routes.push({ method, path, regex, keys, handler });
    }
    match(req) {
        const method = req.method || 'GET';
        const url = req.url?.split('?')[0] || '/';
        for (const route of this.routes) {
            if (route.method !== method)
                continue;
            const match = url.match(route.regex);
            if (!match)
                continue;
            const params = {};
            for (let i = 0; i < route.keys.length; i++) {
                params[route.keys[i]] = match[i + 1];
            }
            return { handler: route.handler, params };
        }
        return null;
    }
    compilePath(path) {
        const keys = [];
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
class AryaCoreImpl extends events_1.EventEmitter {
    constructor() {
        super();
        this.router = new Router();
        this.middlewares = [];
        this.activeServer = null;
        this.errorHandler = (err, _req, res) => {
            res.status(500).send(`Internal Server Error: ${err.message}`);
        };
    }
    use(arg1, arg2) {
        if (typeof arg1 === 'string' && arg2) {
            this.middlewares.push({ path: arg1, handler: arg2 });
        }
        else if (typeof arg1 === 'function') {
            this.middlewares.push({ handler: arg1 });
        }
        return this;
    }
    get(path, handler) {
        this.router.addRoute('GET', path, handler);
        return this;
    }
    post(path, handler) {
        this.router.addRoute('POST', path, handler);
        return this;
    }
    put(path, handler) {
        this.router.addRoute('PUT', path, handler);
        return this;
    }
    delete(path, handler) {
        this.router.addRoute('DELETE', path, handler);
        return this;
    }
    patch(path, handler) {
        this.router.addRoute('PATCH', path, handler);
        return this;
    }
    options(path, handler) {
        this.router.addRoute('OPTIONS', path, handler);
        return this;
    }
    onError(handler) {
        this.errorHandler = handler;
    }
    enhanceResponse(res) {
        const enhancedRes = res;
        enhancedRes.send = (body) => {
            if (typeof body === 'object') {
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(body));
            }
            else {
                res.setHeader('Content-Type', 'text/plain');
                res.end(body);
            }
            return enhancedRes;
        };
        enhancedRes.json = (body) => {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(body));
            return enhancedRes;
        };
        enhancedRes.status = (code) => {
            res.statusCode = code;
            return enhancedRes;
        };
        enhancedRes.set = (key, value) => {
            res.setHeader(key, value);
            return enhancedRes;
        };
        return enhancedRes;
    }
    parseQuery(url) {
        const query = {};
        try {
            const queryString = new url_1.URL(url, 'http://localhost').searchParams;
            queryString.forEach((value, key) => {
                query[key] = value;
            });
        }
        catch (e) {
            const queryString = url.split('?')[1];
            if (queryString) {
                queryString.split('&').forEach(pair => {
                    const [key, value] = pair.split('=');
                    if (key)
                        query[decodeURIComponent(key)] = decodeURIComponent(value || '');
                });
            }
        }
        return query;
    }
    parseRequestBody(req) {
        return new Promise((resolve, reject) => {
            if (req.method === 'GET' || req.method === 'HEAD') {
                return resolve();
            }
            let body = '';
            req.on('data', (chunk) => {
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
                }
                catch (e) {
                    reject(e);
                }
            });
            req.on('error', (err) => {
                reject(err);
            });
        });
    }
    async processRequest(req, res) {
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
                if (res.writableEnded)
                    return;
            }
            // Process path-specific middlewares
            const urlPath = req.url?.split('?')[0] || '/';
            for (const { path, handler } of this.middlewares.filter(m => m.path)) {
                if (!path || urlPath.startsWith(path)) {
                    await this.runMiddleware(handler, req, res);
                    if (res.writableEnded)
                        return;
                }
            }
            // Find matching route
            const route = this.router.match(req);
            if (route) {
                req.params = route.params;
                await this.runHandler(route.handler, req, res);
            }
            else {
                res.status(404).send('Not Found');
            }
        }
        catch (err) {
            this.errorHandler(err, req, res);
        }
    }
    runMiddleware(middleware, req, res) {
        return new Promise((resolve, reject) => {
            const next = (err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            };
            try {
                middleware(req, res, next);
            }
            catch (err) {
                reject(err);
            }
        });
    }
    async runHandler(handler, req, res) {
        const result = handler(req, res);
        if (result instanceof Promise) {
            await result;
        }
    }
    listen(port, callback) {
        this.activeServer = http_1.default.createServer(async (req, res) => {
            const enhancedReq = req;
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
            console.log(`\x1b[36m${banner}\x1b[0m`); // Cyan color
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
function getIPAddress() {
    const interfaces = os_1.default.networkInterfaces();
    for (const devName in interfaces) {
        const iface = interfaces[devName];
        if (!iface)
            continue;
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
function createApp() {
    return new AryaCoreImpl();
}
// CommonJS Export
const createAppCJS = createApp;
exports.default = createAppCJS;
// For CommonJS environment
if (typeof module !== 'undefined' && module.exports) {
    module.exports = createAppCJS;
    module.exports.createApp = createApp;
    module.exports.cors = cors;
    module.exports.rateLimit = rateLimit;
    module.exports.AryaCore = AryaCoreImpl;
    module.exports.MemoryStore = MemoryStore;
}
