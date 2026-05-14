import { useEffect, useRef, useState } from "react";

export function useWebSocket() {
  const [messages, setMessages] = useState([]);
  const [lastMessage, setLastMessage] = useState(null);
  const [status, setStatus] = useState("connecting");

  const wsRef = useRef(null);
  const pingIntervalRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const connect = () => {
    setStatus("connecting");

    const ws = new WebSocket("ws://localhost:8000/ws/incidents");
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("connected");

      pingIntervalRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send("ping");
        }
      }, 30000);
    };

    ws.onmessage = (event) => {
      let data;

      try {
        data = JSON.parse(event.data);
      } catch {
        data = event.data;
      }

      setMessages((prev) => [...prev, data]);
      setLastMessage(data);
    };

    ws.onclose = () => {
      setStatus("disconnected");

      clearInterval(pingIntervalRef.current);

      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };
  };

  useEffect(() => {
    connect();

    return () => {
      wsRef.current?.close();
      clearInterval(pingIntervalRef.current);
      clearTimeout(reconnectTimeoutRef.current);
    };
  }, []);

  return {
    messages,
    lastMessage,
    status,
  };
}