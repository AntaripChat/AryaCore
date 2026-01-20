import http, { IncomingMessage, ServerResponse } from 'http';
type Handler = (req: AryaCoreRequest, res: AryaCoreResponse) => void | Promise<void>;
type Middleware = (req: AryaCoreRequest, res: AryaCoreResponse, next: (err?: any) => void) => void;
type ErrorHandler = (err: any, req: AryaCoreRequest, res: AryaCoreResponse) => void;
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
interface RateLimitOptions {
    windowMs?: number;
    max?: number;
    message?: string;
    statusCode?: number;
    skipSuccessfulRequests?: boolean;
    skipFailedRequests?: boolean;
    keyGenerator?: (req: AryaCoreRequest) => string;
    skip?: (req: AryaCoreRequest) => boolean;
    onLimitReached?: (req: AryaCoreRequest) => void;
    store?: RateLimitStore;
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
export declare function rateLimit(options?: RateLimitOptions): Middleware;
export declare function cors(options?: CorsOptions): Middleware;
export declare function createApp(): AryaCore;
declare const createAppCJS: typeof createApp;
export default createAppCJS;
