/**
 * DevPulse - VS Code Extension API Integration
 * Real HTTP calls to the DevPulse backend
 */

import * as vscode from 'vscode';
import axios, { AxiosError } from 'axios';

export class DevPulseAPIClient {
  private apiBaseUrl: string;
  private authToken: string | undefined;

  constructor() {
    this.apiBaseUrl = vscode.workspace.getConfiguration('devpulse').get('apiUrl') || 'http://localhost:8000';
    this.authToken = vscode.workspace.getConfiguration('devpulse').get('authToken');
  }

  /**
   * Authenticate with the DevPulse API
   */
  async authenticate(email: string, password: string): Promise<{ token: string; user_id: string }> {
    try {
      const response = await axios.post(`${this.apiBaseUrl}/api/auth/login`, {
        email,
        password,
      });
      
      this.authToken = response.data.token;
      await vscode.workspace.getConfiguration('devpulse').update('authToken', this.authToken, vscode.ConfigurationTarget.Global);
      
      return {
        token: response.data.token,
        user_id: response.data.user_id,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * List all collections for the authenticated user
   */
  async listCollections(): Promise<any[]> {
    if (!this.authToken) {
      throw new Error('Not authenticated. Please authenticate first.');
    }

    try {
      const response = await axios.get(`${this.apiBaseUrl}/api/collections`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      return response.data.collections || [];
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get details of a specific collection
   */
  async getCollection(collectionId: string): Promise<any> {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }

    try {
      const response = await axios.get(`${this.apiBaseUrl}/api/collections/${collectionId}`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Run a security scan on a collection
   */
  async scanCollection(collectionId: string): Promise<{ scan_id: string; risk_score: number; total_findings: number; findings: any[] }> {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }

    try {
      const response = await axios.post(
        `${this.apiBaseUrl}/api/scan/collection`,
        { collection_id: collectionId },
        { headers: { Authorization: `Bearer ${this.authToken}` } }
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get scan results
   */
  async getScanResults(scanId: string): Promise<any> {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }

    try {
      const response = await axios.get(`${this.apiBaseUrl}/api/scans/${scanId}`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get risk score metrics
   */
  async getRiskMetrics(): Promise<any> {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }

    try {
      const response = await axios.get(`${this.apiBaseUrl}/api/risk-score`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get token usage analytics
   */
  async getTokenAnalytics(): Promise<any> {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }

    try {
      const response = await axios.get(`${this.apiBaseUrl}/api/tokens/analytics`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Trigger the kill switch
   */
  async triggerKillSwitch(reason: string): Promise<{ success: boolean; message: string }> {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }

    try {
      const response = await axios.post(
        `${this.apiBaseUrl}/api/kill-switch/trigger`,
        { reason },
        { headers: { Authorization: `Bearer ${this.authToken}` } }
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Generate a compliance report
   */
  async generateComplianceReport(collectionId: string, reportType: string): Promise<any> {
    if (!this.authToken) {
      throw new Error('Not authenticated');
    }

    try {
      const response = await axios.post(
        `${this.apiBaseUrl}/api/compliance/report`,
        { collection_id: collectionId, report_type: reportType },
        { headers: { Authorization: `Bearer ${this.authToken}` } }
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Handle API errors
   */
  private handleError(error: any): Error {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError;
      if (axiosError.response?.status === 401) {
        this.authToken = undefined;
        return new Error('Authentication failed. Please log in again.');
      }
      if (axiosError.response?.status === 403) {
        return new Error('Access denied. You do not have permission to access this resource.');
      }
      if (axiosError.response?.status === 404) {
        return new Error('Resource not found.');
      }
      return new Error(`API Error: ${axiosError.message}`);
    }
    return new Error(`Unexpected error: ${String(error)}`);
  }

  /**
   * Check if authenticated
   */
  isAuthenticated(): boolean {
    return !!this.authToken;
  }

  /**
   * Clear authentication
   */
  logout(): void {
    this.authToken = undefined;
    vscode.workspace.getConfiguration('devpulse').update('authToken', undefined, vscode.ConfigurationTarget.Global);
  }
}

export default DevPulseAPIClient;
