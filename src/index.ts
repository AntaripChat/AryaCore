import http, { IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';
import { URL } from 'url';
import os from 'os';

// ====================== Core Types ======================
type Handler = (req: AryaCoreRequest, res: AryaCoreResponse) => void | Promise<void>;
type Middleware = (req: AryaCoreRequest, res: AryaCoreResponse, next: (err?: any) => void) => void;
type ErrorHandler = (err: any, req: AryaCoreRequest, res: AryaCoreResponse) => void;

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
      queryString.forEach((value, key) => {
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
      req.on('data', chunk => {
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
      
      req.on('error', (err) => {
        reject(err);
      });
    });
  }

  private async processRequest(req: AryaCoreRequest, res: AryaCoreResponse) {
    try {
      // Parse query parameters
      req.query = this.parseQuery(req.url || '/');
      
      // Parse request body for POST, PUT, PATCH requests
      if (['POST', 'PUT', 'PATCH'].includes(req.method || '')) {
        await this.parseRequestBody(req);
      }
      
      // Process global middlewares
      for (const { handler } of this.middlewares.filter(m => !m.path)) {
        await this.runMiddleware(handler, req, res);
        if (res.writableEnded) return;
      }
      
      // Process path-specific middlewares
      const urlPath = req.url?.split('?')[0] || '/';
      for (const { path, handler } of this.middlewares.filter(m => m.path)) {
        if (!path || urlPath.startsWith(path)) {
          await this.runMiddleware(handler, req, res);
          if (res.writableEnded) return;
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
    this.activeServer = http.createServer(async (req, res) => {
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
module.exports = createAppCJS;
module.exports.createApp = createApp;
module.exports.AryaCore = AryaCoreImpl;