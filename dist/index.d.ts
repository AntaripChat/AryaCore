import http, { IncomingMessage, ServerResponse } from 'http';
type Handler = (req: AryaCoreRequest, res: AryaCoreResponse) => void | Promise<void>;
type Middleware = (req: AryaCoreRequest, res: AryaCoreResponse, next: (err?: any) => void) => void;
type ErrorHandler = (err: any, req: AryaCoreRequest, res: AryaCoreResponse) => void;
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
export declare function createApp(): AryaCore;
declare const createAppCJS: typeof createApp;
export default createAppCJS;
