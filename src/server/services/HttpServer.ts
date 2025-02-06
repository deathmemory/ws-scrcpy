import * as http from 'http';
import * as https from 'https';
import path from 'path';
import { Service } from './Service';
import { Utils } from '../Utils';
import express, { Express, Request, Response, NextFunction } from 'express';
import { Config } from '../Config';
import { TypedEmitter } from '../../common/TypedEmitter';
import * as process from 'process';
import { EnvName } from '../EnvName';
import * as crypto from 'crypto';
import cookieParser from 'cookie-parser';
import * as fs from 'fs';

const DEFAULT_STATIC_DIR = path.join(__dirname, './public');

const PATHNAME = process.env[EnvName.WS_SCRCPY_PATHNAME] || __PATHNAME__;

// 设置密码和令牌存储
let PASSWORD = 'dmemory';
try {
    PASSWORD = fs.readFileSync(path.join(__dirname, '../config/password.txt')).toString().trim();
} catch (e) {
    // 如果读取失败则使用默认密码
}
const validTokens = new Set<string>();

export type ServerAndPort = {
    server: https.Server | http.Server;
    port: number;
};

interface HttpServerEvents {
    started: boolean;
}

export class HttpServer extends TypedEmitter<HttpServerEvents> implements Service {
    private static instance: HttpServer;
    private static PUBLIC_DIR = DEFAULT_STATIC_DIR;
    private static SERVE_STATIC = true;
    private servers: ServerAndPort[] = [];
    private mainApp?: Express;
    private started = false;

    protected constructor() {
        super();
    }

    public static getInstance(): HttpServer {
        if (!this.instance) {
            this.instance = new HttpServer();
        }
        return this.instance;
    }

    public static hasInstance(): boolean {
        return !!this.instance;
    }

    public static setPublicDir(dir: string): void {
        if (HttpServer.instance) {
            throw Error('Unable to change value after instantiation');
        }
        HttpServer.PUBLIC_DIR = dir;
    }

    public static setServeStatic(enabled: boolean): void {
        if (HttpServer.instance) {
            throw Error('Unable to change value after instantiation');
        }
        HttpServer.SERVE_STATIC = enabled;
    }

    public async getServers(): Promise<ServerAndPort[]> {
        if (this.started) {
            return [...this.servers];
        }
        return new Promise<ServerAndPort[]>((resolve) => {
            this.once('started', () => {
                resolve([...this.servers]);
            });
        });
    }

    public getName(): string {
        return `HTTP(s) Server Service`;
    }

    public async start(): Promise<void> {
        this.mainApp = express();
        this.mainApp.use(cookieParser());
        this.mainApp.use(express.json());
        
        // 添加身份验证中间件
        this.mainApp.use((req: Request, res: Response, next: NextFunction) => {
            // 允许访问静态资源、登录页面和验证接口
            if (req.path === '/login' || 
                req.path === '/auth' || 
                req.path.startsWith('/static/') ||
                req.path.startsWith('/favicon.ico')) {
                return next();
            }

            // 检查认证令牌
            const token = req.cookies?.authToken;
            if (token && validTokens.has(token)) {
                return next();
            }

            // 未验证则重定向到登录页面
            if (req.headers.accept?.includes('text/html')) {
                res.redirect('/login');
            } else {
                res.status(401).json({ success: false, message: '未授权访问' });
            }
        });

        // 添加登录页面路由
        this.mainApp.get('/login', (req: Request, res: Response) => {
            res.sendFile(path.join(__dirname, '../src/public/login.html'));
        });

        // 添加验证接口
        this.mainApp.post('/auth', (req: Request, res: Response) => {
            const { password } = req.body;
            if (password === PASSWORD) {
                const token = crypto.randomBytes(32).toString('hex');
                validTokens.add(token);
                res.cookie('authToken', token, { 
                    httpOnly: true,
                    maxAge: 24 * 60 * 60 * 1000 // 24小时有效期
                });
                res.json({ success: true });
            } else {
                res.status(401).json({ success: false, message: '密码错误' });
            }
        });

        if (HttpServer.SERVE_STATIC && HttpServer.PUBLIC_DIR) {
            this.mainApp.use(PATHNAME, express.static(HttpServer.PUBLIC_DIR));

            /// #if USE_WDA_MJPEG_SERVER

            const { MjpegProxyFactory } = await import('../mw/MjpegProxyFactory');
            this.mainApp.get('/mjpeg/:udid', new MjpegProxyFactory().proxyRequest);
            /// #endif
        }
        const config = Config.getInstance();
        config.servers.forEach((serverItem) => {
            const { secure, port, redirectToSecure } = serverItem;
            let proto: string;
            let server: http.Server | https.Server;
            if (secure) {
                if (!serverItem.options) {
                    throw Error('Must provide option for secure server configuration');
                }
                server = https.createServer(serverItem.options, this.mainApp);
                proto = 'https';
            } else {
                const options = serverItem.options ? { ...serverItem.options } : {};
                proto = 'http';
                let currentApp = this.mainApp;
                let host = '';
                let port = 443;
                let doRedirect = false;
                if (redirectToSecure === true) {
                    doRedirect = true;
                } else if (typeof redirectToSecure === 'object') {
                    doRedirect = true;
                    if (typeof redirectToSecure.port === 'number') {
                        port = redirectToSecure.port;
                    }
                    if (typeof redirectToSecure.host === 'string') {
                        host = redirectToSecure.host;
                    }
                }
                if (doRedirect) {
                    currentApp = express();
                    currentApp.use(function (_req, res) {
                        const url = new URL(`https://${host ? host : _req.headers.host}${_req.url}`);
                        if (port && port !== 443) {
                            url.port = port.toString();
                        }
                        return res.redirect(301, url.toString());
                    });
                }
                server = http.createServer(options, currentApp);
            }
            this.servers.push({ server, port });
            server.listen(port, () => {
                Utils.printListeningMsg(proto, port, PATHNAME);
            });
        });
        this.started = true;
        this.emit('started', true);
    }

    public release(): void {
        this.servers.forEach((item) => {
            item.server.close();
        });
    }
}
