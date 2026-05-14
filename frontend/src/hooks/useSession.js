import { useEffect, useState } from "react";
import { api } from "../api/argus";

export function useSession() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const checkSession = async () => {
    try {
      const res = await api.health();

      if (res.ok) {
        setIsAuthenticated(true);
      } else {
        setIsAuthenticated(false);
      }
    } catch (err) {
      setError("Session check failed");
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkSession();
  }, []);

  const login = async (password) => {
    setLoading(true);
    setError(null);

    try {
      const res = await api.login(password);
      if (!res.ok) {
        setError("Invalid password");
        setIsAuthenticated(false);
        return false;
      }

      setIsAuthenticated(true);
      return true;
    } catch (err) {
      setError("Login failed");
      return false;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    await api.logout();
    setIsAuthenticated(false);
  };

  return {
    isAuthenticated,
    login,
    logout,
    loading,
    error,
  };
}