import http, { IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';
import { URL } from 'url';
import os from 'os';
import fs from 'fs';
import path from 'path';
import child_process from 'child_process';
import dotenv from 'dotenv';

// ====================== Enhanced Core ======================
dotenv.config(); // Load environment variables

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
  query?: Record<string, string | string[]>;
  body?: any;
  cookies?: Record<string, string>;
}

interface AryaCoreResponse extends ServerResponse {
  send: (body: any) => AryaCoreResponse;
  status: (code: number) => AryaCoreResponse;
  json: (body: object) => AryaCoreResponse;
  set: (key: string, value: string) => AryaCoreResponse;
  cookie: (name: string, value: string, options?: CookieOptions) => AryaCoreResponse;
  clearCookie: (name: string) => AryaCoreResponse;
  sendFile: (filePath: string) => Promise<AryaCoreResponse>;
  redirect: (url: string) => AryaCoreResponse;
}

interface CookieOptions {
  maxAge?: number;
  expires?: Date;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
}

interface AryaCore {
  use(middleware: Middleware): AryaCore;
  use(path: string, middleware: Middleware): AryaCore;
  static(prefix: string, dir: string): AryaCore;
  get(path: string, handler: Handler): AryaCore;
  post(path: string, handler: Handler): AryaCore;
  put(path: string, handler: Handler): AryaCore;
  delete(path: string, handler: Handler): AryaCore;
  patch(path: string, handler: Handler): AryaCore;
  options(path: string, handler: Handler): AryaCore;
  onError(handler: ErrorHandler): void;
  listen(port: number, callback?: () => void): http.Server;
  close(): void;
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
  private server: http.Server | null = null;
  private staticDirs: { prefix: string; dir: string }[] = [];

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

  static(prefix: string, dir: string): AryaCore {
    this.staticDirs.push({ prefix, dir });
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

    enhancedRes.cookie = (name: string, value: string, options: CookieOptions = {}) => {
      let cookie = `${name}=${value}`;
      
      if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
      if (options.expires) cookie += `; Expires=${options.expires.toUTCString()}`;
      if (options.httpOnly) cookie += '; HttpOnly';
      if (options.secure) cookie += '; Secure';
      if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
      
      res.setHeader('Set-Cookie', cookie);
      return enhancedRes;
    };

    enhancedRes.clearCookie = (name: string) => {
      res.setHeader('Set-Cookie', `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
      return enhancedRes;
    };

    enhancedRes.sendFile = async (filePath: string) => {
      try {
        const data = await fs.promises.readFile(filePath);
        const ext = path.extname(filePath);
        const mimeTypes: Record<string, string> = {
          '.html': 'text/html',
          '.js': 'text/javascript',
          '.css': 'text/css',
          '.json': 'application/json',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.gif': 'image/gif',
          '.svg': 'image/svg+xml',
        };
        
        res.setHeader('Content-Type', mimeTypes[ext] || 'application/octet-stream');
        res.end(data);
      } catch (err) {
        this.errorHandler(err, {} as AryaCoreRequest, enhancedRes);
      }
      return enhancedRes;
    };

    enhancedRes.redirect = (url: string) => {
      res.statusCode = 302;
      res.setHeader('Location', url);
      res.end();
      return enhancedRes;
    };
    
    return enhancedRes;
  }

  private parseQuery(url: string): Record<string, string | string[]> {
    const query: Record<string, string | string[]> = {};
    try {
      const queryString = new URL(url, 'http://localhost').searchParams;
      queryString.forEach((value, key) => {
        if (query[key]) {
          if (Array.isArray(query[key])) {
            (query[key] as string[]).push(value);
          } else {
            query[key] = [query[key] as string, value];
          }
        } else {
          query[key] = value;
        }
      });
    } catch (e) {
      const queryString = url.split('?')[1];
      if (queryString) {
        queryString.split('&').forEach(pair => {
          const [key, value] = pair.split('=');
          if (key) {
            const decodedKey = decodeURIComponent(key);
            if (query[decodedKey]) {
              if (Array.isArray(query[decodedKey])) {
                (query[decodedKey] as string[]).push(decodeURIComponent(value || ''));
              } else {
                query[decodedKey] = [query[decodedKey] as string, decodeURIComponent(value || '')];
              }
            } else {
              query[decodedKey] = decodeURIComponent(value || '');
            }
          }
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
          else if (contentType.includes('multipart/form-data') && body) {
            // Simplified multipart parsing
            req.body = {};
            const boundary = contentType.split('boundary=')[1];
            const parts = body.split(`--${boundary}`);
            parts.forEach((part: string) => {
              const match = part.match(/name="([^"]+)"\s*\r?\n\r?\n([\s\S]*)\r?\n--/);
              if (match) {
                req.body[match[1]] = match[2].trim();
              }
            });
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
      // Parse cookies
      req.cookies = {};
      const cookieHeader = req.headers.cookie;
      if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
          const [name, value] = cookie.trim().split('=');
          if (name && value) req.cookies![name] = value;
        });
      }
      
      // Parse query parameters
      req.query = this.parseQuery(req.url || '/');
      
      // Check static files
      for (const { prefix, dir } of this.staticDirs) {
        const url = req.url || '/';
        if (url.startsWith(prefix)) {
          const filePath = path.join(dir, url.slice(prefix.length));
          if (await this.serveStaticFile(filePath, res)) {
            return;
          }
        }
      }
      
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

  private async serveStaticFile(filePath: string, res: AryaCoreResponse): Promise<boolean> {
    try {
      const stats = await fs.promises.stat(filePath);
      if (stats.isDirectory()) {
        const indexPath = path.join(filePath, 'index.html');
        if (fs.existsSync(indexPath)) {
          await res.sendFile(indexPath);
          return true;
        }
        return false;
      }
      
      await res.sendFile(filePath);
      return true;
    } catch {
      return false;
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
    this.server = http.createServer(async (req, res) => {
      const enhancedReq = req as AryaCoreRequest;
      const enhancedRes = this.enhanceResponse(res);
      
      await this.processRequest(enhancedReq, enhancedRes);
    });

    return this.server.listen(port, () => {
      const banner = `
    █████╗ ██████╗ ██╗   ██╗ █████╗      ██████╗ ██████╗ ██████╗ ███████╗
   ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗██╔════╝
   ███████║██████╔╝ ╚████╔╝ ███████║    ██║     ██║   ██║██████╔╝█████╗  
   ██╔══██║██╔══██╗  ╚██╔╝  ██╔══██║    ██║     ██║   ██║██╔══██╗██╔══╝  
   ██║  ██║██║  ██║   ██║   ██║  ██║    ╚██████╗╚██████╔╝██║  ██║███████╗
   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
      `;

      console.log(`\x1b[36m${banner}\x1b[0m`);
      console.log(`\x1b[32m🚀 Server running on port \x1b[33m${port}\x1b[0m`);
      console.log(`\x1b[90m➜ Local:   \x1b[0m\x1b[36mhttp://localhost:${port}/\x1b[0m`);
      console.log(`\x1b[90m➜ Network: \x1b[0m\x1b[36mhttp://${getIPAddress()}:${port}/\x1b[0m`);
      
      // Auto-open browser in development
      if (process.env.NODE_ENV === 'development') {
        child_process.exec(`open http://localhost:${port}`);
      }

      if (callback) callback();
    });
  }

  close() {
    if (this.server) {
      this.server.close();
      console.log('\x1b[31mServer stopped\x1b[0m');
    }
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

// ====================== CLI Support ======================
class AryaCLI {
  constructor() {
    this.setupCommands();
  }

  private setupCommands() {
    const command = process.argv[2];
    
    switch (command) {
      case 'new':
        this.createProject(process.argv[3]);
        break;
      case 'start':
        this.startServer();
        break;
      case 'generate':
        this.generateComponent(process.argv[3], process.argv[4]);
        break;
      case '--version':
        this.showVersion();
        break;
      default:
        this.showHelp();
    }
  }

  private createProject(projectName?: string) {
    if (!projectName) {
      console.error('\x1b[31mPlease specify a project name:\x1b[0m');
      console.log('  arya new <project-name>');
      process.exit(1);
    }

    console.log(`\x1b[36mCreating new Arya project: ${projectName}\x1b[0m`);
    
    // Create project structure
    const projectPath = path.join(process.cwd(), projectName);
    fs.mkdirSync(projectPath, { recursive: true });
    
    // Create basic files
    const files = {
      'index.ts': `import { createApp } from 'arya-core';\n\nconst app = createApp();\n\napp.get('/', (req, res) => {\n  res.send('Hello from Arya!');\n});\n\napp.listen(3000, () => {\n  console.log('Server started on port 3000');\n});`,
      '.gitignore': 'node_modules/\n.env\n',
      'package.json': JSON.stringify({
        name: projectName,
        version: '1.0.0',
        scripts: {
          start: 'ts-node index.ts',
          dev: 'NODE_ENV=development ts-node index.ts'
        },
        dependencies: {
          'arya-core': '^1.0.0',
          dotenv: '^16.0.0'
        },
        devDependencies: {
          'ts-node': '^10.9.1',
          typescript: '^5.0.4'
        }
      }, null, 2),
      'tsconfig.json': JSON.stringify({
        compilerOptions: {
          target: 'ES2020',
          module: 'CommonJS',
          esModuleInterop: true,
          skipLibCheck: true,
          forceConsistentCasingInFileNames: true
        }
      }, null, 2)
    };

    // Write files
    Object.entries(files).forEach(([fileName, content]) => {
      fs.writeFileSync(path.join(projectPath, fileName), content);
    });

    console.log('\x1b[32mProject created successfully!\x1b[0m');
    console.log(`\nNext steps:
  cd ${projectName}
  npm install
  npm run dev`);
  }

  private startServer() {
    require('ts-node/register'); // Enable TypeScript execution
    const appPath = path.join(process.cwd(), 'index.ts');
    
    if (!fs.existsSync(appPath)) {
      console.error('\x1b[31mNo index.ts file found in current directory\x1b[0m');
      process.exit(1);
    }
    
    require(appPath);
  }

  private generateComponent(type: string, name?: string) {
    if (!name) {
      console.error('\x1b[31mPlease specify a name:\x1b[0m');
      console.log('  arya generate <type> <name>');
      process.exit(1);
    }

    switch (type) {
      case 'route':
        this.generateRoute(name);
        break;
      case 'middleware':
        this.generateMiddleware(name);
        break;
      case 'controller':
        this.generateController(name);
        break;
      default:
        console.error(`\x1b[31mUnknown component type: ${type}\x1b[0m`);
        this.showHelp();
    }
  }

  private generateRoute(name: string) {
    const routesDir = path.join(process.cwd(), 'src', 'routes');
    fs.mkdirSync(routesDir, { recursive: true });
    
    const routeContent = `import { createApp } from 'arya-core';\n\nconst router = createApp();\n\nrouter.get('/', (req, res) => {\n  res.send('${name} route working');\n});\n\nexport default router;`;
    fs.writeFileSync(path.join(routesDir, `${name}.route.ts`), routeContent);
    
    console.log(`\x1b[32mRoute created: src/routes/${name}.route.ts\x1b[0m`);
  }

  private generateMiddleware(name: string) {
    const middlewareDir = path.join(process.cwd(), 'src', 'middleware');
    fs.mkdirSync(middlewareDir, { recursive: true });
    
    const middlewareContent = `import { AryaCoreRequest, AryaCoreResponse } from 'arya-core';\n\nexport default function ${name}(req: AryaCoreRequest, res: AryaCoreResponse, next: () => void) {\n  // Middleware logic here\n  console.log('${name} middleware executed');\n  next();\n}`;
    fs.writeFileSync(path.join(middlewareDir, `${name}.middleware.ts`), middlewareContent);
    
    console.log(`\x1b[32mMiddleware created: src/middleware/${name}.middleware.ts\x1b[0m`);
  }

  private generateController(name: string) {
    const controllerDir = path.join(process.cwd(), 'src', 'controllers');
    fs.mkdirSync(controllerDir, { recursive: true });
    
    const controllerContent = `export default class ${name}Controller {\n  static index(req, res) {\n    res.send('${name} controller working');\n  }\n}`;
    fs.writeFileSync(path.join(controllerDir, `${name}.controller.ts`), controllerContent);
    
    console.log(`\x1b[32mController created: src/controllers/${name}.controller.ts\x1b[0m`);
  }

  private showVersion() {
    console.log('\x1b[36mArya Core Framework v2.0.0\x1b[0m');
  }

  private showHelp() {
    console.log('\x1b[36mArya Core Framework CLI\x1b[0m');
    console.log('\nUsage: arya <command> [options]');
    console.log('\nCommands:');
    console.log('  new <project-name>    Create a new project');
    console.log('  start                 Start the development server');
    console.log('  generate <type> <name>  Generate component (route, middleware, controller)');
    console.log('  --version             Show version information');
    console.log('\nExamples:');
    console.log('  arya new my-app');
    console.log('  arya generate route users');
    console.log('  arya start');
  }
}

// ====================== Execution ======================
if (require.main === module) {
  if (process.argv.length > 2 && !process.argv[1].includes('ts-node')) {
    // CLI execution
    new AryaCLI();
  } else {
    // Framework execution
    const app = createApp();
    
    // Example routes
    app.get('/', (req, res) => {
      res.send('Hello from Arya Core!');
    });
    
    app.get('/api/users', (req, res) => {
      res.json([{ id: 1, name: 'John' }, { id: 2, name: 'Jane' }]);
    });
    
    app.listen(3000);
  }
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