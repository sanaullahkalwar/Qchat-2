import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

export interface QuantumKeys {
  publicKey: string;
  secretKey: string;
}

export interface SharedSecretResponse {
  ciphertext: string;
  sharedSecret: string;
}

export interface ChatSession {
  userId: number;
  sharedSecret: string;
  ciphertext: string;
}

@Injectable({
  providedIn: 'root'
})
export class QuantumService {
  private apiUrl = 'http://localhost:3000';
  private sessions: Map<number, ChatSession> = new Map();

  constructor(private http: HttpClient) {}

  /**
   * Get or generate quantum keys for current user
   */
  getOrGenerateKeys(): Observable<QuantumKeys> {
    return this.http.post<QuantumKeys>(`${this.apiUrl}/quantum/generate-keys`, {});
  }

  /**
   * Get another user's public key
   */
  getUserPublicKey(userId: number): Observable<{ publicKey: string; hasKeys: boolean }> {
    return this.http.get<{ publicKey: string; hasKeys: boolean }>(
      `${this.apiUrl}/quantum/public-key/${userId}`
    );
  }

  /**
   * Check if current user has quantum keys
   */
  checkQuantumStatus(): Observable<{ hasQuantumKeys: boolean }> {
    return this.http.get<{ hasQuantumKeys: boolean }>(`${this.apiUrl}/quantum/status`);
  }

  /**
   * Initialize a quantum chat session with another user
   */
  async initQuantumSession(userId: number, recipientPublicKey: string): Promise<ChatSession> {
    // Create shared secret
    const response = await this.http.post<SharedSecretResponse>(
      `${this.apiUrl}/quantum/create-secret`,
      { recipientPublicKey }
    ).toPromise();

    const session: ChatSession = {
      userId: userId,
      sharedSecret: response!.sharedSecret,
      ciphertext: response!.ciphertext
    };

    // Store session
    this.sessions.set(userId, session);
    
    // Store in localStorage for persistence
    this.saveSessionsToStorage();
    
    return session;
  }

  /**
   * Get existing quantum session for a user
   */
  getQuantumSession(userId: number): ChatSession | undefined {
    return this.sessions.get(userId);
  }

  /**
   * Encrypt a message using shared secret
   */
  async encryptMessage(message: string, sharedSecretBase64: string): Promise<string> {
    const encoder = new TextEncoder();
    const sharedSecret = this.base64ToBuffer(sharedSecretBase64);
    const key = sharedSecret.slice(0, 32);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      encoder.encode(message)
    );
    
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), iv.length);
    
    return this.bufferToBase64(result);
  }

  /**
   * Decrypt a message using shared secret
   */
  async decryptMessage(encryptedBase64: string, sharedSecretBase64: string): Promise<string> {
    const decoder = new TextDecoder();
    const encrypted = this.base64ToBuffer(encryptedBase64);
    const sharedSecret = this.base64ToBuffer(sharedSecretBase64);
    const key = sharedSecret.slice(0, 32);
    
    const iv = encrypted.slice(0, 12);
    const ciphertext = encrypted.slice(12);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      ciphertext
    );
    
    return decoder.decode(decrypted);
  }

  /**
   * Save sessions to localStorage
   */
  private saveSessionsToStorage() {
    const sessionsArray = Array.from(this.sessions.entries());
    localStorage.setItem('quantum_sessions', JSON.stringify(sessionsArray));
  }

  /**
   * Load sessions from localStorage
   */
  loadSessionsFromStorage() {
    const stored = localStorage.getItem('quantum_sessions');
    if (stored) {
      const sessionsArray = JSON.parse(stored);
      this.sessions = new Map(sessionsArray);
    }
  }

  private base64ToBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private bufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < buffer.length; i++) {
      binary += String.fromCharCode(buffer[i]);
    }
    return btoa(binary);
  }
}