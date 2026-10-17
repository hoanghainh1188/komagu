export interface Persona {
  userId: string;
  displayName: string;
  tenantId: string;
  tenantName: string;
  role: string;
  mockToken: string;
}

export interface Order {
  id: string;
  tenantId: string;
  ownerUserId: string;
  totalAmount: number;
  status: string;
  description: string;
  createdAt: string;
}

export interface DocumentItem {
  id: string;
  tenantId: string;
  ownerUserId: string;
  title: string;
  content: string;
  isConfidential: boolean;
  createdAt: string;
}

export const DEFAULT_PERSONAS: Persona[] = [
  {
    userId: 'user-a',
    displayName: 'Alice (User A - Owner)',
    tenantId: 'tenant-alpha',
    tenantName: 'Alpha Corporation',
    role: 'member',
    mockToken: 'token-user-a',
  },
  {
    userId: 'user-b',
    displayName: 'Bob (User B - Attacker/Peer)',
    tenantId: 'tenant-alpha',
    tenantName: 'Alpha Corporation',
    role: 'member',
    mockToken: 'token-user-b',
  },
  {
    userId: 'user-c',
    displayName: 'Charlie (User C - Cross-Tenant)',
    tenantId: 'tenant-beta',
    tenantName: 'Beta Holdings',
    role: 'member',
    mockToken: 'token-user-c',
  },
];

export class ApiClient {
  private baseUrl: string;
  private token: string;

  constructor(baseUrl: string = '', token: string = 'token-user-a') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.token = token;
  }

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<{ status: number; data?: T; error?: string }> {
    const headers = new Headers(options.headers || {});
    if (this.token) {
      headers.set('Authorization', `Bearer ${this.token}`);
    }
    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    try {
      const resp = await fetch(`${this.baseUrl}${path}`, {
        ...options,
        headers,
      });

      const text = await resp.text();
      let parsed: any = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = text;
      }

      if (!resp.ok) {
        return {
          status: resp.status,
          error: typeof parsed === 'object' && parsed?.error ? parsed.error : `HTTP ${resp.status}`,
        };
      }

      return { status: resp.status, data: parsed };
    } catch (err: any) {
      return { status: 0, error: err.message || 'Network error' };
    }
  }

  getOrders() {
    return this.request<Order[]>('/api/v1/orders');
  }

  getOrder(id: string) {
    return this.request<Order>(`/api/v1/orders/${id}`);
  }

  getLegacyOrder(id: string) {
    return this.request<Order>(`/api/v1/test/legacy-orders/${id}`);
  }

  getDocuments() {
    return this.request<DocumentItem[]>('/api/v1/documents');
  }

  searchLegacy(query: string) {
    return this.request<Order[]>(`/api/v1/test/legacy-search?query=${encodeURIComponent(query)}`);
  }
}
