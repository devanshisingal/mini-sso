const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export interface User {
  id: string;
  email: string;
  is_admin: boolean;
  has_mfa: boolean;
  created_at: string;
}

export interface ClientApp {
  id: string;
  client_id: string;
  name: string;
  redirect_uris: string[];
  allowed_cidrs?: string[];
  created_at: string;
}

export interface AuditLogItem {
  id: number;
  timestamp: string;
  user_id?: string;
  client_id?: string;
  event: string;
  outcome: string;
  ip?: string;
  user_agent?: string;
  details?: string;
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...options.headers,
    },
    credentials: 'include', // Include HttpOnly cookies
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorMsg = data.detail || response.statusText || 'Request failed';
    throw new Error(errorMsg);
  }

  return data as T;
}

export const api = {
  async register(email: string, password: string): Promise<User> {
    return request<User>('/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async login(email: string, password: string): Promise<{
    status: 'authenticated' | 'mfa_required';
    message: string;
    next_step?: string;
    user?: User;
  }> {
    return request('/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  async enrollMfa(): Promise<{
    secret: string;
    provisioning_uri: string;
    qr_code_svg: string;
  }> {
    return request('/mfa/enroll', {
      method: 'POST',
    });
  },

  async verifyMfa(code: string): Promise<{
    status: string;
    message: string;
    user?: User;
  }> {
    return request('/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
  },

  async getMe(): Promise<User> {
    return request<User>('/me', {
      method: 'GET',
    });
  },

  async logout(): Promise<void> {
    await request('/logout', {
      method: 'POST',
    });
  },

  async listClients(): Promise<ClientApp[]> {
    return request<ClientApp[]>('/admin/clients', {
      method: 'GET',
    });
  },

  async createClient(client: {
    client_id: string;
    name: string;
    redirect_uris: string[];
    allowed_cidrs?: string[];
  }): Promise<ClientApp> {
    return request<ClientApp>('/admin/clients', {
      method: 'POST',
      body: JSON.stringify(client),
    });
  },

  async getAuditLogs(): Promise<AuditLogItem[]> {
    return request<AuditLogItem[]>('/admin/audit-log?limit=100', {
      method: 'GET',
    });
  },
};
