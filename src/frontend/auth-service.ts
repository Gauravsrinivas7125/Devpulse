/**
 * DevPulse - Frontend Auth Service
 * Handles authentication API calls and token management
 */

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface SignupCredentials {
  email: string;
  password: string;
  name: string;
  company?: string;
}

export interface AuthResponse {
  success: boolean;
  token?: string;
  user_id?: string;
  error?: string;
}

export class AuthService {
  static async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
      });

      const data = await response.json();
      
      if (response.ok && data.token) {
        // Store token in localStorage
        localStorage.setItem('devpulse_token', data.token);
        localStorage.setItem('devpulse_user_id', data.user_id);
        return { success: true, token: data.token, user_id: data.user_id };
      }
      
      return { success: false, error: data.detail || 'Login failed' };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  static async signup(credentials: SignupCredentials): Promise<AuthResponse> {
    try {
      const response = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
      });

      const data = await response.json();
      
      if (response.ok && data.token) {
        // Store token in localStorage
        localStorage.setItem('devpulse_token', data.token);
        localStorage.setItem('devpulse_user_id', data.user_id);
        return { success: true, token: data.token, user_id: data.user_id };
      }
      
      return { success: false, error: data.detail || 'Signup failed' };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  static logout(): void {
    localStorage.removeItem('devpulse_token');
    localStorage.removeItem('devpulse_user_id');
  }

  static getToken(): string | null {
    return localStorage.getItem('devpulse_token');
  }

  static getUserId(): string | null {
    return localStorage.getItem('devpulse_user_id');
  }

  static isAuthenticated(): boolean {
    return !!this.getToken();
  }

  static getAuthHeader() {
    const token = this.getToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  }
}

export default AuthService;
