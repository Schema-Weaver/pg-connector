/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, no-empty */
import * as http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { WakeEvent } from '../channels/types';
import { deserialize, serializeToBytes, deserializeFromBytes } from '../protocol/serialize';
import { AgentMessage } from '../protocol/envelope';

export interface MockRelayOptions {
  port?: number;  // 0 = random free port
  /** Tokens that are accepted for wake channel auth. */
  validTokens?: string[];
  /** If true, return 401 for all wake requests. */
  rejectAuth?: boolean;
  /** If true, send a wake event every N ms automatically. */
  autoWakeIntervalMs?: number;
}

export interface MockRelay {
  port: number;
  /** Push a wake event to the connected agent. */
  pushWakeEvent(event: WakeEvent): void;
  /** Echo the last received data channel message back to the agent. */
  echoLastMessage(): void;
  /** Send a custom message to the agent over the data channel. */
  sendMessageToAgent(msg: unknown): void;
  /** Get all messages received from agent on data channel. */
  getReceivedMessages(): unknown[];
  /** Stop the relay. */
  stop(): Promise<void>;
}

export async function startMockRelay(opts: MockRelayOptions = {}): Promise<MockRelay> {
  const validTokens = opts.validTokens || [];
  const rejectAuth = opts.rejectAuth || false;

  let activeSseRes: http.ServerResponse | null = null;
  let activeWs: WebSocket | null = null;
  const receivedMessages: unknown[] = [];
  let autoWakeTimer: NodeJS.Timeout | undefined;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
    
    if (url.pathname === '/agent/wake') {
      const auth = req.headers.authorization;
      const token = auth && auth.startsWith('Bearer ') ? auth.substring(7) : null;
      
      const isAuthorized = !rejectAuth && (validTokens.length === 0 || (token && validTokens.includes(token)));
      
      if (!isAuthorized) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_token' }));
        return;
      }

      // Upgrade to SSE
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });

      // Keep connection open
      res.write(': ping\n\n'); // send initial comment event
      
      if (activeSseRes) {
        try {
          activeSseRes.end();
        } catch (e) {}
      }
      activeSseRes = res;

      req.on('close', () => {
        if (activeSseRes === res) {
          activeSseRes = null;
        }
      });
      return;
    }

    res.writeHead(404);
    res.end();
  });

  const wss = new WebSocketServer({ noServer: true });
  const wssBrowser = new WebSocketServer({ noServer: true });
  const browserWses = new Set<WebSocket>();

  server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
    if (url.pathname === '/agent/data') {
      const token = url.searchParams.get('token') || '';
      
      const isAuthorized = !rejectAuth && (validTokens.length === 0 || validTokens.includes(token));
      
      if (!isAuthorized) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else if (url.pathname === '/wss') {
      wssBrowser.handleUpgrade(request, socket, head, (ws) => {
        wssBrowser.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  wss.on('connection', (ws) => {
    console.log('MockRelay: Agent WebSocket connected');
    activeWs = ws;

    ws.on('message', (data, isBinary) => {
      let msg: any;
      try {
        if (isBinary) {
          msg = deserializeFromBytes(new Uint8Array(data as Buffer));
        } else {
          msg = deserialize(data.toString());
        }
      } catch (err) {
        try {
          msg = JSON.parse(data.toString());
        } catch (_) {
          msg = data.toString();
        }
      }

      receivedMessages.push(msg);

      // Forward to all browser clients
      const jsonStr = typeof msg === 'string' ? msg : JSON.stringify(msg);
      for (const browserWs of browserWses) {
        if (browserWs.readyState === WebSocket.OPEN) {
          browserWs.send(jsonStr);
        }
      }
    });

    ws.on('close', () => {
      if (activeWs === ws) {
        activeWs = null;
      }
    });
  });

  wssBrowser.on('connection', (ws) => {
    console.log('MockRelay: Browser WebSocket connected');
    browserWses.add(ws);

    ws.on('message', (data) => {
      let msg: any;
      try {
        msg = JSON.parse(data.toString());
      } catch (err) {
        console.error('MockRelay: Failed to parse browser JSON:', err);
        return;
      }

      // Forward to agent as binary
      if (activeWs && activeWs.readyState === WebSocket.OPEN) {
        const bytes = serializeToBytes(msg);
        activeWs.send(bytes);
      } else {
        console.warn('MockRelay: Browser message dropped, agent not connected');
      }
    });

    ws.on('close', () => {
      browserWses.delete(ws);
    });
  });

  return new Promise<MockRelay>((resolve, reject) => {
    server.listen(opts.port !== undefined ? opts.port : 0, '127.0.0.1', () => {
      const addr = server.address();
      const actualPort = typeof addr === 'object' && addr !== null ? addr.port : 0;

      if (opts.autoWakeIntervalMs) {
        autoWakeTimer = setInterval(() => {
          if (activeSseRes) {
            const wakeEvent: WakeEvent = {
              wake_id: 'auto-ping-' + Date.now(),
              reason: 'ping',
              queued_at: Date.now(),
              data_channel_token: 'auto-token',
              data_channel_token_expires_at: Date.now() + 60000,
            };
            activeSseRes.write(`data: ${JSON.stringify(wakeEvent)}\n\n`);
          }
        }, opts.autoWakeIntervalMs);
      }

      resolve({
        port: actualPort,
        pushWakeEvent(event: WakeEvent): void {
          if (activeSseRes) {
            activeSseRes.write(`data: ${JSON.stringify(event)}\n\n`);
          }
        },
        echoLastMessage(): void {
          const last = receivedMessages[receivedMessages.length - 1];
          if (last && activeWs && activeWs.readyState === WebSocket.OPEN) {
            const bytes = serializeToBytes(last as AgentMessage);
            activeWs.send(bytes);
          }
        },
        sendMessageToAgent(msg: unknown): void {
          if (activeWs && activeWs.readyState === WebSocket.OPEN) {
            const bytes = serializeToBytes(msg as AgentMessage);
            activeWs.send(bytes);
          }
        },
        getReceivedMessages(): unknown[] {
          return receivedMessages;
        },
        async stop(): Promise<void> {
          if (autoWakeTimer) {
            clearInterval(autoWakeTimer);
          }
          if (activeSseRes) {
            try {
              activeSseRes.end();
            } catch (err) {}
          }
          if (activeWs) {
            try {
              activeWs.close();
            } catch (err) {}
          }
          for (const bws of browserWses) {
            try {
              bws.close();
            } catch (err) {}
          }
          browserWses.clear();
          wss.close();
          wssBrowser.close();
          return new Promise<void>((resolveClose) => {
            server.unref();
            server.close(() => {
              resolveClose();
            });
            setTimeout(() => resolveClose(), 500).unref();
          });
        }
      });
    });

    server.on('error', (err) => {
      reject(err);
    });
  });
}
