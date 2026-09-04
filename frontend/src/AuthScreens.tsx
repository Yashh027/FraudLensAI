import { useState } from "react";
import { useAuth } from "./AuthContext";
import {
  Shield,
  Mail,
  Lock,
  AlertCircle,
  Loader2,
  Eye,
  EyeOff,
} from "lucide-react";

export function LoginScreen({ onSwitchToRegister }: { onSwitchToRegister: () => void }) {
  const { login, isLoading: authLoading } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);
    try {
      await login(email, password);
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-icon">
            <Shield size={48} />
          </div>
          <h1>Welcome Back</h1>
          <p>Sign in to access your FraudLens dashboard</p>
        </div>

        {error && <div className="auth-error"><AlertCircle size={16} /> {error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="email">Email</label>
            <div className="input-with-icon">
              <Mail size={18} />
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                required
                autoComplete="email"
                disabled={isLoading || authLoading}
              />
            </div>
          </div>

          <div className="auth-field">
            <label htmlFor="password">Password</label>
            <div className="input-with-icon">
              <Lock size={18} />
              <input
                id="password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                autoComplete="current-password"
                disabled={isLoading || authLoading}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                disabled={isLoading || authLoading}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="auth-submit"
            disabled={isLoading || authLoading}
          >
            {isLoading || authLoading ? (
              <>
                <Loader2 size={18} className="spin" />
                Signing in...
              </>
            ) : (
              "Sign In"
            )}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            Don't have an account?{" "}
            <button type="button" className="auth-link" onClick={onSwitchToRegister}>
              Create one
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}

export function RegisterScreen({ onSwitchToLogin }: { onSwitchToLogin: () => void }) {
  const { register, isLoading: authLoading } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setError("");
    setIsLoading(true);
    try {
      await register(email, password);
    } catch (err: any) {
      setError(err.message || "Registration failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-icon">
            <Shield size={48} />
          </div>
          <h1>Create Account</h1>
          <p>Join FraudLens to start scanning</p>
        </div>

        {error && <div className="auth-error"><AlertCircle size={16} /> {error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="reg-email">Email</label>
            <div className="input-with-icon">
              <Mail size={18} />
              <input
                id="reg-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                required
                autoComplete="email"
                disabled={isLoading || authLoading}
              />
            </div>
          </div>

          <div className="auth-field">
            <label htmlFor="reg-password">Password</label>
            <div className="input-with-icon">
              <Lock size={18} />
              <input
                id="reg-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="•••••••• (min 8 chars)"
                required
                autoComplete="new-password"
                disabled={isLoading || authLoading}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                disabled={isLoading || authLoading}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <div className="auth-field">
            <label htmlFor="reg-confirm">Confirm Password</label>
            <div className="input-with-icon">
              <Lock size={18} />
              <input
                id="reg-confirm"
                type={showPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                required
                autoComplete="new-password"
                disabled={isLoading || authLoading}
              />
            </div>
          </div>

          <button
            type="submit"
            className="auth-submit"
            disabled={isLoading || authLoading}
          >
            {isLoading || authLoading ? (
              <>
                <Loader2 size={18} className="spin" />
                Creating account...
              </>
            ) : (
              "Create Account"
            )}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            Already have an account?{" "}
            <button type="button" className="auth-link" onClick={onSwitchToLogin}>
              Sign in
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}