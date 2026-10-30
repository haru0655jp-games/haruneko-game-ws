import http from "node:http";
import crypto from "node:crypto";
import { WebSocketServer, WebSocket } from "ws";

/* =========================================================
 * 設定（環境変数）
 * ======================================================= */
const PORT = Number(process.env.PORT || 8080);

// 認証トークン。カンマ区切りで複数指定でき、入れ替え（ローテーション）時に新旧を併用できる
const AUTH_TOKENS = (process.env.AUTH_TOKENS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// 接続を許可するブラウザのオリジン
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Originヘッダーを持たないクライアント（アプリ・スクリプト等）を許可するか
const ALLOW_NO_ORIGIN = process.env.ALLOW_NO_ORIGIN === "true";

if (AUTH_TOKENS.length === 0) throw new Error("AUTH_TOKENS を設定してください");
if (AUTH_TOKENS.some((t) => t.length < 16)) throw new Error("トークンは16文字以上にしてください");
if (ALLOWED_ORIGINS.length === 0 && !ALLOW_NO_ORIGIN) {
  throw new Error("ALLOWED_ORIGINS を設定してください（または ALLOW_NO_ORIGIN=true）");
}

const MAX_PAYLOAD_BYTES = 16 * 1024; // 1メッセージの最大サイズ
const MAX_TEXT_CHARS = 2000; // チャット1件の最大文字数
const MSG_MAX = 20; // 10秒あたりの送信上限
const MSG_WINDOW_MS = 10_000;
const MAX_CONN_TOTAL = 5000;
const MAX_CONN_PER_IP = 20;
const MAX_BUFFERED_BYTES = 1024 * 1024; // 送信が詰まった接続は切る
const AUTH_FAIL_MAX = 20; // 認証失敗はIPごとに1分あたり20回まで
const AUTH_FAIL_WINDOW_MS = 60_000;

/* =========================================================
 * 補助関数
 * ======================================================= */
const sha256 = (s) => crypto.createHash("sha256").update(s).digest();
const tokenDigests = AUTH_TOKENS.map(sha256);

// 長さの違いが漏れないよう、ハッシュ同士を一定時間で比較する
function tokenValid(token) {
  if (typeof token !== "string" || token.length === 0 || token.length > 256) return false;
  const d = sha256(token);
  let ok = false;
  for (const x of tokenDigests) if (crypto.timingSafeEqual(d, x)) ok = true;
  return ok;
}

// Renderのプロキシが付ける X-Forwarded-For の先頭をクライアントIPとして使う
function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff) return xff.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

const CONTROL_RE = /[\u0000-\u001f\u007f]/;
function sanitizeName(raw, fallback) {
  const name = String(raw ?? "").trim();
  return name.length >= 1 && name.length <= 32 && !CONTROL_RE.test(name) ? name : fallback;
}

// 認証失敗の回数制限（総当たり対策）
const authFails = new Map(); // ip -> { count, reset }
function authFailAllowed(ip) {
  const e = authFails.get(ip);
  return !e || e.reset <= Date.now() || e.count < AUTH_FAIL_MAX;
}
function recordAuthFail(ip) {
  const now = Date.now();
  const e = authFails.get(ip);
  if (!e || e.reset <= now) authFails.set(ip, { count: 1, reset: now + AUTH_FAIL_WINDOW_MS });
  else e.count += 1;
}

/* =========================================================
 * HTTP（ヘルスチェックのみ）
 * ======================================================= */
const server = http.createServer((req, res) => {
  const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (req.method === "GET" && req.url === "/healthz") {
    res.writeHead(200, { "Content-Type": "text/plain", ...headers });
    return res.end("ok");
  }
  res.writeHead(404, headers);
  res.end();
});

server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 65_000; // Renderのプロキシより長くする

/* =========================================================
 * WebSocket（/chat/:roomId?token=...&name=...）
 * ======================================================= */
const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD_BYTES });
const rooms = new Map(); // roomId -> Set<ws>
const ipConns = new Map(); // ip -> 接続数

server.on("upgrade", (req, socket, head) => {
  socket.on("error", () => {});
  const reject = (status) => {
    socket.write(
      `HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`
    );
    socket.destroy();
  };

  const ip = clientIp(req);
  const url = new URL(req.url, "http://localhost");

  // Origin確認
  const origin = req.headers.origin;
  if (origin) {
    if (!ALLOWED_ORIGINS.includes(origin)) return reject(403);
  } else if (!ALLOW_NO_ORIGIN) {
    return reject(403);
  }

  // パス確認
  const match = url.pathname.match(/^\/chat\/([A-Za-z0-9_-]{1,64})$/);
  if (!match) return reject(404);

  // トークン確認
  if (!authFailAllowed(ip)) return reject(429);
  if (!tokenValid(url.searchParams.get("token"))) {
    recordAuthFail(ip);
    return reject(401);
  }

  // 接続数の上限
  if (wss.clients.size >= MAX_CONN_TOTAL) return reject(503);
  if ((ipConns.get(ip) || 0) >= MAX_CONN_PER_IP) return reject(429);

  const roomId = match[1];
  const connId = crypto.randomBytes(4).toString("hex");
  const name = sanitizeName(url.searchParams.get("name"), `guest-${connId}`);

  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.connId = connId;
    ws.userName = name;
    ws.roomId = roomId;
    ws.ip = ip;
    ws.isAlive = true;
    ws.rateCount = 0;
    ws.rateReset = Date.now() + MSG_WINDOW_MS;

    let set = rooms.get(roomId);
    if (!set) rooms.set(roomId, (set = new Set()));
    set.add(ws);
    ipConns.set(ip, (ipConns.get(ip) || 0) + 1);

    ws.on("pong", () => {
      ws.isAlive = true;
    });
    ws.on("error", () => {});
    ws.on("close", () => {
      const room = rooms.get(ws.roomId);
      if (room) {
        room.delete(ws);
        if (room.size === 0) rooms.delete(ws.roomId);
      }
      const n = (ipConns.get(ws.ip) || 1) - 1;
      if (n <= 0) ipConns.delete(ws.ip);
      else ipConns.set(ws.ip, n);
    });

    ws.on("message", (data, isBinary) => {
      if (isBinary) return ws.close(1003, "text only");

      const now = Date.now();
      if (now > ws.rateReset) {
        ws.rateReset = now + MSG_WINDOW_MS;
        ws.rateCount = 0;
      }
      if (++ws.rateCount > MSG_MAX) return ws.close(1008, "rate limit");

      const text = data.toString("utf8").trim();
      if (!text || text.length > MAX_TEXT_CHARS) return;

      const payload = JSON.stringify({
        type: "message",
        roomId: ws.roomId,
        from: { id: ws.connId, name: ws.userName },
        text,
        ts: now,
      });
      for (const client of rooms.get(ws.roomId) || []) {
        if (client.readyState !== WebSocket.OPEN) continue;
        if (client.bufferedAmount > MAX_BUFFERED_BYTES) {
          client.terminate(); // 受信が詰まっている接続は切る
          continue;
        }
        client.send(payload);
      }
    });

    ws.send(
      JSON.stringify({ type: "welcome", roomId, you: { id: ws.connId, name: ws.userName } })
    );
  });
});

/* =========================================================
 * 定期処理
 * ======================================================= */
const timers = [
  // 死んだ接続の検出
  setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) {
        ws.terminate();
        continue;
      }
      ws.isAlive = false;
      ws.ping();
    }
  }, 30_000),

  // 認証失敗の記録を掃除
  setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of authFails) if (e.reset <= now) authFails.delete(ip);
  }, 60_000),
];
timers.forEach((t) => t.unref());

/* =========================================================
 * 起動・終了
 * ======================================================= */
function shutdown(signal) {
  console.log(`${signal} received, shutting down`);
  timers.forEach(clearInterval);
  for (const ws of wss.clients) ws.close(1001, "server shutting down");
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("unhandledRejection", (err) => console.error("unhandledRejection:", err));

server.listen(PORT, "0.0.0.0", () => console.log(`listening on 0.0.0.0:${PORT}`));
