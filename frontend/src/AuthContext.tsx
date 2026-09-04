import { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface User {
  id: number;
  email: string;
  is_active: boolean;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("fraudlens_token"));
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const storedToken = localStorage.getItem("fraudlens_token");
    if (storedToken) {
      // Verify token by fetching user info
      fetch(`${API_BASE}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${storedToken}` },
      })
        .then((res) => {
          if (res.ok) return res.json();
          throw new Error("Invalid token");
        })
        .then((data) => {
          setUser(data);
          setToken(storedToken);
        })
        .catch(() => {
          localStorage.removeItem("fraudlens_token");
          setToken(null);
          setUser(null);
        })
        .finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = async (email: string, password: string) => {
    const formData = new URLSearchParams();
    formData.append("username", email);
    formData.append("password", password);

    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Login failed");
    }

    const data = await res.json();
    const newToken = data.access_token;
    localStorage.setItem("fraudlens_token", newToken);
    setToken(newToken);

    // Fetch user info
    const meRes = await fetch(`${API_BASE}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${newToken}` },
    });
    if (meRes.ok) {
      const userData = await meRes.json();
      setUser(userData);
    }
  };

  const register = async (email: string, password: string) => {
    const res = await fetch(`${API_BASE}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Registration failed");
    }

    // Auto-login after registration
    await login(email, password);
  };

  const logout = () => {
    localStorage.removeItem("fraudlens_token");
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, login, register, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}