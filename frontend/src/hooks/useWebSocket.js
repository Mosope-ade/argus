import { useEffect, useRef, useState, useCallback } from "react";

export function useWebSocket() {
  const [messages, setMessages] = useState([]);
  const [lastMessage, setLastMessage] = useState(null);
  const [status, setStatus] = useState("connecting");

  const wsRef = useRef(null);
  const pingIntervalRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    // Always close any existing connection before opening a new one
    if (wsRef.current) {
      wsRef.current.onclose = null; // prevent reconnect loop from firing
      wsRef.current.close();
      wsRef.current = null;
    }

    if (!mountedRef.current) return;
    setStatus("connecting");

    const wsBase = import.meta.env.VITE_WS_URL || "ws://localhost:8001";
    const ws = new WebSocket(`${wsBase}/ws/incidents`);
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) { ws.close(); return; }
      setStatus("connected");

      pingIntervalRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send("ping");
        }
      }, 30000);
    };

    ws.onmessage = (event) => {
      if (!mountedRef.current) return;
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        data = event.data;
      }
      if (data?.type === "pong") return; // ignore keepalive replies
      setMessages((prev) => [...prev, data]);
      setLastMessage(data);
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setStatus("disconnected");
      clearInterval(pingIntervalRef.current);
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      clearInterval(pingIntervalRef.current);
      clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
    };
  }, [connect]);

  return { messages, lastMessage, status };
}