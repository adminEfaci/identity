# Identity Module API Endpoints Documentation

## Table of Contents
- [Authentication Endpoints](#authentication-endpoints)
- [User Management Endpoints](#user-management-endpoints)
- [MFA Endpoints](#mfa-endpoints)
- [RBAC Endpoints](#rbac-endpoints)
- [Admin Dashboard Endpoints](#admin-dashboard-endpoints)
- [Admin User Management Endpoints](#admin-user-management-endpoints)
- [Admin Audit Log Endpoints](#admin-audit-log-endpoints)
- [Admin System Management Endpoints](#admin-system-management-endpoints)
- [Qwik City Frontend Integration](#qwik-city-frontend-integration)

## Base URL
```
http://localhost:8000
```

## Authentication
All endpoints except login and public endpoints require JWT authentication token in headers:
```
Authorization: Bearer <token>
```

## Response Format
All responses follow this standard format:
```json
{
  "status": "success | error | warning",
  "message": "Human-readable message",
  "timestamp": "2024-01-01T00:00:00Z",
  "request_id": "optional-request-id",
  "data": {} // Response data
}
```

## Authentication Endpoints

### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "password123"
}
```

Response:
```json
{
  "status": "success",
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer",
    "expires_in": 1800,
    "user": {
      "id": "user123",
      "email": "user@example.com",
      "username": "johndoe",
      "roles": ["user"],
      "mfa_enabled": false
    }
  }
}
```

### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### Logout
```http
POST /api/auth/logout
Authorization: Bearer <token>
```

## User Management Endpoints

### Create User
```http
POST /api/users/
Content-Type: application/json

{
  "email": "newuser@example.com",
  "username": "newuser",
  "first_name": "John",
  "last_name": "Doe",
  "password": "SecurePassword123!"
}
```

### Get Users (Paginated)
```http
GET /api/users/?page=1&page_size=20&is_active=true&sort_by=created_at&sort_order=desc
Authorization: Bearer <token>
```

### Get User by ID
```http
GET /api/users/{user_id}
Authorization: Bearer <token>
```

### Update User
```http
PATCH /api/users/{user_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "updated@example.com",
  "first_name": "Jane",
  "is_active": true
}
```

### Delete User
```http
DELETE /api/users/{user_id}
Authorization: Bearer <token>
```

## MFA Endpoints

### Setup MFA
```http
POST /api/mfa/setup
Authorization: Bearer <token>
Content-Type: application/json

{
  "method": "totp"
}
```

Response:
```json
{
  "status": "success",
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code": "data:image/png;base64,...",
    "backup_codes": [
      "12345678",
      "87654321"
    ]
  }
}
```

### Verify MFA Setup
```http
POST /api/mfa/verify-setup
Authorization: Bearer <token>
Content-Type: application/json

{
  "method": "totp",
  "code": "123456"
}
```

### Verify MFA Code
```http
POST /api/mfa/verify
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "123456"
}
```

### Disable MFA
```http
DELETE /api/mfa/disable
Authorization: Bearer <token>
```

## RBAC Endpoints

### Get Roles
```http
GET /api/rbac/roles
Authorization: Bearer <token>
```

### Create Role
```http
POST /api/rbac/roles
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "moderator",
  "description": "Content moderator role",
  "permissions": ["content:read", "content:update", "content:delete"]
}
```

### Update Role
```http
PUT /api/rbac/roles/{role_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "description": "Updated description",
  "permissions": ["content:read", "content:update"]
}
```

### Delete Role
```http
DELETE /api/rbac/roles/{role_id}
Authorization: Bearer <token>
```

### Assign Role to User
```http
POST /api/rbac/users/{user_id}/roles
Authorization: Bearer <token>
Content-Type: application/json

{
  "role_ids": ["role1", "role2"]
}
```

## Admin Dashboard Endpoints

### Dashboard Overview
```http
GET /api/admin/dashboard/overview
Authorization: Bearer <token>
```

Response:
```json
{
  "status": "success",
  "data": {
    "stats": {
      "total_users": 1250,
      "active_users": 1100,
      "inactive_users": 150,
      "users_with_mfa": 450,
      "total_roles": 15,
      "total_permissions": 75,
      "active_sessions": 234,
      "failed_login_attempts_24h": 12
    },
    "health": {
      "status": "healthy",
      "database": {"status": "connected", "latency_ms": 2.5},
      "redis": {"status": "connected", "latency_ms": 0.8},
      "api_latency_ms": 25.4,
      "error_rate": 0.02,
      "uptime_seconds": 864000
    },
    "recent_activities": [...],
    "user_growth_7d": [...],
    "alerts": [...]
  }
}
```

### System Statistics
```http
GET /api/admin/dashboard/stats
Authorization: Bearer <token>
```

### System Health
```http
GET /api/admin/dashboard/health
Authorization: Bearer <token>
```

### Recent Activities
```http
GET /api/admin/dashboard/activities?page=1&page_size=20&activity_type=user_login&date_from=2024-01-01
Authorization: Bearer <token>
```

### User Growth Statistics
```http
GET /api/admin/dashboard/user-growth?days=30
Authorization: Bearer <token>
```

## Admin User Management Endpoints

### Search Users (Advanced)
```http
GET /api/admin/users/search?query=john&role=admin&is_active=true&mfa_enabled=true&page=1&page_size=20
Authorization: Bearer <token>
```

### Get User Details (Admin View)
```http
GET /api/admin/users/{user_id}
Authorization: Bearer <token>
```

### Bulk User Operations
```http
POST /api/admin/users/bulk-operation
Authorization: Bearer <token>
Content-Type: application/json

{
  "user_ids": ["user1", "user2", "user3"],
  "operation": "activate",
  "parameters": {}
}
```

### Assign Roles to User
```http
POST /api/admin/users/{user_id}/roles
Authorization: Bearer <token>
Content-Type: application/json

{
  "role_ids": ["admin", "moderator"],
  "replace": false
}
```

### Lock User Account
```http
POST /api/admin/users/{user_id}/lock
Authorization: Bearer <token>
Content-Type: application/json

{
  "reason": "Suspicious activity detected",
  "duration_minutes": 60,
  "notify_user": true
}
```

### Reset User Password
```http
POST /api/admin/users/{user_id}/reset-password
Authorization: Bearer <token>
Content-Type: application/json

{
  "temporary_password": null,
  "require_change": true,
  "notify_user": true
}
```

### Get User Analytics
```http
GET /api/admin/users/{user_id}/analytics
Authorization: Bearer <token>
```

## Admin Audit Log Endpoints

### Get Audit Logs
```http
GET /api/admin/audit/logs?page=1&page_size=20&event_type=user_login&severity=warning&date_from=2024-01-01
Authorization: Bearer <token>
```

### Get Audit Log Details
```http
GET /api/admin/audit/logs/{log_id}
Authorization: Bearer <token>
```

### Get Security Events
```http
GET /api/admin/audit/security-events?threat_level=high&requires_review=true
Authorization: Bearer <token>
```

### Review Security Event
```http
POST /api/admin/audit/security-events/{event_id}/review?notes=Reviewed&action_taken=account_locked
Authorization: Bearer <token>
```

### Get Audit Statistics
```http
GET /api/admin/audit/statistics?date_from=2024-01-01&date_to=2024-01-31
Authorization: Bearer <token>
```

### Export Audit Logs
```http
POST /api/admin/audit/export
Authorization: Bearer <token>
Content-Type: application/json

{
  "format": "csv",
  "date_from": "2024-01-01T00:00:00Z",
  "date_to": "2024-01-31T23:59:59Z",
  "event_types": ["user_login", "user_logout"],
  "include_details": true
}
```

## Admin System Management Endpoints

### Get System Configuration
```http
GET /api/admin/system/configuration?category=security&show_sensitive=false
Authorization: Bearer <token>
```

### Update Configuration
```http
PUT /api/admin/system/configuration/{config_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "value": 16
}
```

### Get Feature Flags
```http
GET /api/admin/system/feature-flags
Authorization: Bearer <token>
```

### Update Feature Flag
```http
PUT /api/admin/system/feature-flags/{flag_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "enabled": true,
  "rollout_percentage": 75,
  "target_roles": ["beta_tester"]
}
```

### Maintenance Mode
```http
GET /api/admin/system/maintenance
Authorization: Bearer <token>

PUT /api/admin/system/maintenance
Authorization: Bearer <token>
Content-Type: application/json

{
  "enabled": true,
  "message": "System maintenance in progress",
  "start_time": "2024-01-01T02:00:00Z",
  "end_time": "2024-01-01T04:00:00Z",
  "allowed_ips": ["192.168.1.0/24"],
  "allowed_users": ["admin1", "admin2"]
}
```

### System Backups
```http
GET /api/admin/system/backups
Authorization: Bearer <token>

POST /api/admin/system/backups?backup_type=full&include_audit_logs=true
Authorization: Bearer <token>
```

### Cache Management
```http
GET /api/admin/system/cache
Authorization: Bearer <token>

POST /api/admin/system/cache/flush?pattern=session:*&confirm=true
Authorization: Bearer <token>
```

# Qwik City Frontend Integration

## Installation

```bash
npm install @tanstack/qwik-query axios
```

## API Client Setup

Create `src/lib/api-client.ts`:

```typescript
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { useSignal, useTask$ } from '@builder.io/qwik';

const API_BASE_URL = import.meta.env.PUBLIC_API_URL || 'http://localhost:8000';

class ApiClient {
  private client: AxiosInstance;
  private token: string | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        if (this.token) {
          config.headers.Authorization = `Bearer ${this.token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response.data,
      async (error) => {
        if (error.response?.status === 401) {
          // Handle token refresh
          await this.refreshToken();
        }
        return Promise.reject(error);
      }
    );
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('access_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }

  async refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
      throw new Error('No refresh token');
    }

    try {
      const response = await this.client.post('/api/auth/refresh', {
        refresh_token: refreshToken,
      });
      
      this.setToken(response.data.access_token);
      localStorage.setItem('refresh_token', response.data.refresh_token);
      
      return response.data;
    } catch (error) {
      this.clearToken();
      throw error;
    }
  }

  // Generic request methods
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.client.get(url, config);
  }

  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.client.post(url, data, config);
  }

  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.client.put(url, data, config);
  }

  async patch<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.client.patch(url, data, config);
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.client.delete(url, config);
  }
}

export const apiClient = new ApiClient();
```

## Authentication Service

Create `src/services/auth.service.ts`:

```typescript
import { apiClient } from '~/lib/api-client';

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: {
    id: string;
    email: string;
    username: string;
    roles: string[];
    mfa_enabled: boolean;
  };
}

export interface MFAVerifyRequest {
  code: string;
}

export class AuthService {
  static async login(credentials: LoginRequest): Promise<LoginResponse> {
    const response = await apiClient.post<any>('/api/auth/login', credentials);
    
    if (response.data.access_token) {
      apiClient.setToken(response.data.access_token);
      localStorage.setItem('refresh_token', response.data.refresh_token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    
    return response.data;
  }

  static async logout(): Promise<void> {
    try {
      await apiClient.post('/api/auth/logout');
    } finally {
      apiClient.clearToken();
      localStorage.removeItem('user');
    }
  }

  static async verifyMFA(code: string): Promise<any> {
    return apiClient.post('/api/mfa/verify', { code });
  }

  static async setupMFA(method: string = 'totp'): Promise<any> {
    return apiClient.post('/api/mfa/setup', { method });
  }

  static getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  }

  static isAuthenticated(): boolean {
    return !!localStorage.getItem('access_token');
  }

  static hasRole(role: string): boolean {
    const user = this.getCurrentUser();
    return user?.roles?.includes(role) || false;
  }

  static isAdmin(): boolean {
    return this.hasRole('admin');
  }
}
```

## User Management Service

Create `src/services/users.service.ts`:

```typescript
import { apiClient } from '~/lib/api-client';

export interface User {
  id: string;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateUserRequest {
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  password: string;
}

export interface UpdateUserRequest {
  email?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
  is_active?: boolean;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    total: number;
    page: number;
    page_size: number;
    total_pages: number;
    has_next: boolean;
    has_prev: boolean;
  };
}

export class UsersService {
  static async getUsers(params?: {
    page?: number;
    page_size?: number;
    is_active?: boolean;
    sort_by?: string;
    sort_order?: 'asc' | 'desc';
  }): Promise<PaginatedResponse<User>> {
    const response = await apiClient.get<any>('/api/users/', { params });
    return response;
  }

  static async getUser(userId: string): Promise<User> {
    const response = await apiClient.get<any>(`/api/users/${userId}`);
    return response.data;
  }

  static async createUser(user: CreateUserRequest): Promise<User> {
    const response = await apiClient.post<any>('/api/users/', user);
    return response.data;
  }

  static async updateUser(userId: string, updates: UpdateUserRequest): Promise<User> {
    const response = await apiClient.patch<any>(`/api/users/${userId}`, updates);
    return response.data;
  }

  static async deleteUser(userId: string): Promise<void> {
    await apiClient.delete(`/api/users/${userId}`);
  }
}
```

## Admin Dashboard Service

Create `src/services/admin.service.ts`:

```typescript
import { apiClient } from '~/lib/api-client';

export interface DashboardStats {
  total_users: number;
  active_users: number;
  inactive_users: number;
  users_with_mfa: number;
  total_roles: number;
  total_permissions: number;
  active_sessions: number;
  failed_login_attempts_24h: number;
}

export interface SystemHealth {
  status: string;
  database: any;
  redis: any;
  api_latency_ms: number;
  error_rate: number;
  uptime_seconds: number;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  event_type: string;
  user_id?: string;
  action: string;
  result: string;
  ip_address?: string;
  details: any;
}

export class AdminService {
  static async getDashboardOverview(): Promise<any> {
    const response = await apiClient.get<any>('/api/admin/dashboard/overview');
    return response.data;
  }

  static async getSystemStats(): Promise<DashboardStats> {
    const response = await apiClient.get<any>('/api/admin/dashboard/stats');
    return response.data;
  }

  static async getSystemHealth(): Promise<SystemHealth> {
    const response = await apiClient.get<any>('/api/admin/dashboard/health');
    return response.data;
  }

  static async getAuditLogs(params?: {
    page?: number;
    page_size?: number;
    event_type?: string;
    severity?: string;
    date_from?: string;
    date_to?: string;
  }): Promise<any> {
    const response = await apiClient.get<any>('/api/admin/audit/logs', { params });
    return response;
  }

  static async searchUsers(params: {
    query?: string;
    email?: string;
    role?: string;
    is_active?: boolean;
    page?: number;
    page_size?: number;
  }): Promise<any> {
    const response = await apiClient.get<any>('/api/admin/users/search', { params });
    return response;
  }

  static async lockUser(userId: string, data: {
    reason: string;
    duration_minutes?: number;
    notify_user: boolean;
  }): Promise<any> {
    const response = await apiClient.post<any>(`/api/admin/users/${userId}/lock`, data);
    return response.data;
  }

  static async resetUserPassword(userId: string, data: {
    temporary_password?: string;
    require_change: boolean;
    notify_user: boolean;
  }): Promise<any> {
    const response = await apiClient.post<any>(`/api/admin/users/${userId}/reset-password`, data);
    return response.data;
  }
}
```

## Qwik Components Examples

### Login Component

Create `src/routes/login/index.tsx`:

```tsx
import { component$, useSignal, $ } from '@builder.io/qwik';
import { useNavigate } from '@builder.io/qwik-city';
import { AuthService } from '~/services/auth.service';

export default component$(() => {
  const nav = useNavigate();
  const username = useSignal('');
  const password = useSignal('');
  const error = useSignal('');
  const loading = useSignal(false);
  const showMFA = useSignal(false);
  const mfaCode = useSignal('');

  const handleLogin = $(async () => {
    loading.value = true;
    error.value = '';

    try {
      const response = await AuthService.login({
        username: username.value,
        password: password.value,
      });

      if (response.user.mfa_enabled) {
        showMFA.value = true;
      } else {
        await nav('/dashboard');
      }
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Login failed';
    } finally {
      loading.value = false;
    }
  });

  const handleMFAVerify = $(async () => {
    loading.value = true;
    error.value = '';

    try {
      await AuthService.verifyMFA(mfaCode.value);
      await nav('/dashboard');
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Invalid MFA code';
    } finally {
      loading.value = false;
    }
  });

  return (
    <div class="login-container">
      <h1>Login</h1>
      
      {!showMFA.value ? (
        <form preventdefault:submit onSubmit$={handleLogin}>
          <div>
            <label>Username/Email</label>
            <input
              type="text"
              value={username.value}
              onInput$={(e) => (username.value = (e.target as HTMLInputElement).value)}
              required
            />
          </div>
          
          <div>
            <label>Password</label>
            <input
              type="password"
              value={password.value}
              onInput$={(e) => (password.value = (e.target as HTMLInputElement).value)}
              required
            />
          </div>
          
          {error.value && <div class="error">{error.value}</div>}
          
          <button type="submit" disabled={loading.value}>
            {loading.value ? 'Logging in...' : 'Login'}
          </button>
        </form>
      ) : (
        <form preventdefault:submit onSubmit$={handleMFAVerify}>
          <h2>Two-Factor Authentication</h2>
          <p>Enter your authentication code</p>
          
          <div>
            <label>Code</label>
            <input
              type="text"
              value={mfaCode.value}
              onInput$={(e) => (mfaCode.value = (e.target as HTMLInputElement).value)}
              maxLength={6}
              required
            />
          </div>
          
          {error.value && <div class="error">{error.value}</div>}
          
          <button type="submit" disabled={loading.value}>
            {loading.value ? 'Verifying...' : 'Verify'}
          </button>
        </form>
      )}
    </div>
  );
});
```

### Admin Dashboard Component

Create `src/routes/admin/dashboard/index.tsx`:

```tsx
import { component$, useSignal, useTask$ } from '@builder.io/qwik';
import { AdminService } from '~/services/admin.service';

export default component$(() => {
  const dashboardData = useSignal<any>(null);
  const loading = useSignal(true);
  const error = useSignal('');

  useTask$(async () => {
    try {
      const data = await AdminService.getDashboardOverview();
      dashboardData.value = data;
    } catch (err: any) {
      error.value = 'Failed to load dashboard data';
    } finally {
      loading.value = false;
    }
  });

  if (loading.value) {
    return <div>Loading dashboard...</div>;
  }

  if (error.value) {
    return <div class="error">{error.value}</div>;
  }

  const { stats, health, recent_activities, user_growth_7d, alerts } = dashboardData.value || {};

  return (
    <div class="admin-dashboard">
      <h1>Admin Dashboard</h1>
      
      {/* Statistics Cards */}
      <div class="stats-grid">
        <div class="stat-card">
          <h3>Total Users</h3>
          <p class="stat-value">{stats?.total_users || 0}</p>
        </div>
        <div class="stat-card">
          <h3>Active Users</h3>
          <p class="stat-value">{stats?.active_users || 0}</p>
        </div>
        <div class="stat-card">
          <h3>MFA Enabled</h3>
          <p class="stat-value">{stats?.users_with_mfa || 0}</p>
        </div>
        <div class="stat-card">
          <h3>Active Sessions</h3>
          <p class="stat-value">{stats?.active_sessions || 0}</p>
        </div>
      </div>

      {/* System Health */}
      <div class="health-section">
        <h2>System Health</h2>
        <div class="health-status">
          <span class={`status-badge ${health?.status}`}>
            {health?.status || 'unknown'}
          </span>
          <span>API Latency: {health?.api_latency_ms}ms</span>
          <span>Error Rate: {(health?.error_rate * 100).toFixed(2)}%</span>
        </div>
      </div>

      {/* Alerts */}
      {alerts?.length > 0 && (
        <div class="alerts-section">
          <h2>System Alerts</h2>
          {alerts.map((alert: any) => (
            <div key={alert.id} class={`alert alert-${alert.severity}`}>
              {alert.message}
            </div>
          ))}
        </div>
      )}

      {/* Recent Activities */}
      <div class="activities-section">
        <h2>Recent Activities</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>User</th>
              <th>Activity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {recent_activities?.map((activity: any) => (
              <tr key={activity.timestamp}>
                <td>{new Date(activity.timestamp).toLocaleString()}</td>
                <td>{activity.user_email}</td>
                <td>{activity.description}</td>
                <td>
                  <span class={`status-${activity.status}`}>
                    {activity.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
});
```

### User Management Component

Create `src/routes/admin/users/index.tsx`:

```tsx
import { component$, useSignal, useTask$, $ } from '@builder.io/qwik';
import { AdminService } from '~/services/admin.service';

export default component$(() => {
  const users = useSignal<any[]>([]);
  const loading = useSignal(true);
  const searchQuery = useSignal('');
  const currentPage = useSignal(1);
  const totalPages = useSignal(1);

  const loadUsers = $(async () => {
    loading.value = true;
    try {
      const response = await AdminService.searchUsers({
        query: searchQuery.value,
        page: currentPage.value,
        page_size: 20,
      });
      
      users.value = response.data;
      totalPages.value = response.pagination.total_pages;
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      loading.value = false;
    }
  });

  useTask$(() => {
    loadUsers();
  });

  const handleSearch = $(async (e: Event) => {
    e.preventDefault();
    currentPage.value = 1;
    await loadUsers();
  });

  const handleLockUser = $(async (userId: string) => {
    if (confirm('Are you sure you want to lock this user?')) {
      try {
        await AdminService.lockUser(userId, {
          reason: 'Admin action',
          notify_user: true,
        });
        await loadUsers();
      } catch (error) {
        console.error('Failed to lock user:', error);
      }
    }
  });

  const handleResetPassword = $(async (userId: string) => {
    if (confirm('Reset password for this user?')) {
      try {
        await AdminService.resetUserPassword(userId, {
          require_change: true,
          notify_user: true,
        });
        alert('Password reset email sent to user');
      } catch (error) {
        console.error('Failed to reset password:', error);
      }
    }
  });

  return (
    <div class="user-management">
      <h1>User Management</h1>
      
      {/* Search Form */}
      <form onSubmit$={handleSearch} class="search-form">
        <input
          type="text"
          placeholder="Search users..."
          value={searchQuery.value}
          onInput$={(e) => (searchQuery.value = (e.target as HTMLInputElement).value)}
        />
        <button type="submit">Search</button>
      </form>

      {/* Users Table */}
      {loading.value ? (
        <div>Loading users...</div>
      ) : (
        <>
          <table class="users-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Username</th>
                <th>Status</th>
                <th>MFA</th>
                <th>Roles</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.value.map((user) => (
                <tr key={user.id}>
                  <td>{user.id}</td>
                  <td>{user.email}</td>
                  <td>{user.username}</td>
                  <td>
                    <span class={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                      {user.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td>{user.mfa_enabled ? '✓' : '✗'}</td>
                  <td>{user.roles.join(', ')}</td>
                  <td>
                    <button onClick$={() => handleLockUser(user.id)}>
                      Lock
                    </button>
                    <button onClick$={() => handleResetPassword(user.id)}>
                      Reset Password
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          <div class="pagination">
            <button
              disabled={currentPage.value <= 1}
              onClick$={() => {
                currentPage.value--;
                loadUsers();
              }}
            >
              Previous
            </button>
            <span>
              Page {currentPage.value} of {totalPages.value}
            </span>
            <button
              disabled={currentPage.value >= totalPages.value}
              onClick$={() => {
                currentPage.value++;
                loadUsers();
              }}
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
});
```

### Protected Route Middleware

Create `src/routes/layout.tsx`:

```tsx
import { component$, Slot } from '@builder.io/qwik';
import { routeLoader$, useLocation } from '@builder.io/qwik-city';
import { AuthService } from '~/services/auth.service';

export const useAuthCheck = routeLoader$(async ({ redirect, pathname }) => {
  const protectedRoutes = ['/dashboard', '/admin'];
  const adminRoutes = ['/admin'];
  
  const isProtected = protectedRoutes.some(route => pathname.startsWith(route));
  const isAdminRoute = adminRoutes.some(route => pathname.startsWith(route));
  
  if (isProtected && !AuthService.isAuthenticated()) {
    throw redirect(302, '/login');
  }
  
  if (isAdminRoute && !AuthService.isAdmin()) {
    throw redirect(302, '/dashboard');
  }
  
  return {
    isAuthenticated: AuthService.isAuthenticated(),
    user: AuthService.getCurrentUser(),
  };
});

export default component$(() => {
  const location = useLocation();
  const authData = useAuthCheck();
  
  return (
    <>
      {location.url.pathname !== '/login' && (
        <nav>
          <a href="/dashboard">Dashboard</a>
          {authData.value.user?.roles?.includes('admin') && (
            <a href="/admin/dashboard">Admin</a>
          )}
          <button onClick$={() => {
            AuthService.logout();
            window.location.href = '/login';
          }}>
            Logout
          </button>
        </nav>
      )}
      
      <main>
        <Slot />
      </main>
    </>
  );
});
```

## Environment Configuration

Create `.env.local`:

```env
PUBLIC_API_URL=http://localhost:8000
```

## TypeScript Types

Create `src/types/api.types.ts`:

```typescript
export interface ApiResponse<T = any> {
  status: 'success' | 'error' | 'warning';
  message: string;
  timestamp: string;
  request_id?: string;
  data?: T;
  error_code?: string;
  errors?: ErrorDetail[];
}

export interface ErrorDetail {
  field?: string;
  code: string;
  message: string;
}

export interface PaginationMeta {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface User {
  id: string;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  is_verified: boolean;
  mfa_enabled: boolean;
  roles: string[];
  permissions: string[];
  created_at: string;
  updated_at: string;
  last_login?: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description: string;
}
```

## Error Handling

Create `src/lib/error-handler.ts`:

```typescript
import { ApiResponse } from '~/types/api.types';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public details?: any
  ) {
    super(`API Error: ${code}`);
  }
}

export function handleApiError(error: any): string {
  if (error.response?.data) {
    const apiResponse = error.response.data as ApiResponse;
    return apiResponse.message || 'An error occurred';
  }
  
  if (error.message) {
    return error.message;
  }
  
  return 'An unexpected error occurred';
}

export function isAuthError(error: any): boolean {
  return error.response?.status === 401 || error.response?.status === 403;
}
```

## Usage Tips

1. **Authentication Flow**:
   - User logs in → receives tokens → stored in localStorage
   - All API calls automatically include the auth token
   - Token refresh happens automatically on 401 errors

2. **Role-Based Access**:
   - Check roles using `AuthService.hasRole('admin')`
   - Protect routes using route loaders
   - Hide/show UI elements based on roles

3. **Error Handling**:
   - All API errors are standardized
   - Use try-catch blocks in components
   - Show user-friendly error messages

4. **Pagination**:
   - Use page and page_size query parameters
   - Handle pagination metadata in responses
   - Implement pagination controls in UI

5. **Real-time Updates**:
   - Consider WebSockets for real-time features
   - Use polling for dashboard statistics
   - Implement optimistic updates for better UX

This documentation provides a complete reference for all backend endpoints and demonstrates how to integrate them with a Qwik City frontend application.