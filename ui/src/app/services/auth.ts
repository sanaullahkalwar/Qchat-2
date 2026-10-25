import { inject, Injectable, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { API_URL } from '../../environment';

export interface UserRecord {
  id?: number;
  firstName: string;
  lastName: string;
  username: string;
  password: string;
}

export type Algorithm = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024' | 'X25519';
export const SUPPORTED_ALGORITHMS: Algorithm[] = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'X25519'];

export type SigAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
export const SUPPORTED_SIG_ALGORITHMS: SigAlgorithm[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

export interface QuantumKeys {
  publicKey: string;
  secretKey: string;
}

export interface QuantumSession {
  sharedSecret: string;
  ciphertext: string | null;
}

@Injectable({
  providedIn: 'root',
})
export class Auth {
  private readonly AUTH_TOKEN_KEY = 'AuthToken';
  private readonly CURRENT_USER_KEY = 'CurrentUser';
  private readonly QUANTUM_KEYS_KEY = 'QuantumKeys';
  private readonly SIG_KEYS_KEY = 'SigKeys';
  private readonly QUANTUM_SESSIONS_KEY = 'QuantumSessions';
  private readonly SENT_MESSAGE_KEYS_KEY = 'SentMessageKeys';  // Store keys for sent messages
  private readonly platformId = inject(PLATFORM_ID);

  private getStorage(): Storage | null {
    if (isPlatformBrowser(this.platformId)) {
      return localStorage;
    }
    return null;
  }

  // ==================== BASE64 HELPER FUNCTIONS ====================

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const cleanBase64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
    const binaryString = atob(cleanBase64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToBuffer(base64: string): Uint8Array {
    const cleanBase64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
    const binaryString = atob(cleanBase64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
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

  // ==================== QUANTUM ENCRYPTION METHODS ====================

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
    
    // Combine IV + encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    // Convert Uint8Array to ArrayBuffer by using .buffer
    return this.arrayBufferToBase64(combined.buffer);
  }

  async decryptMessage(encryptedBase64: string, sharedSecretBase64: string): Promise<string> {
    const decoder = new TextDecoder();
    
    // Convert from base64 to buffer
    const combined = this.base64ToArrayBuffer(encryptedBase64);
    const combinedArray = new Uint8Array(combined);
    
    // Extract IV (first 12 bytes) and ciphertext (rest)
    const iv = combinedArray.slice(0, 12);
    const ciphertext = combinedArray.slice(12);
    
    const sharedSecret = this.base64ToBuffer(sharedSecretBase64);
    const key = sharedSecret.slice(0, 32);
    
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

  // ==================== QUANTUM KEY MANAGEMENT ====================

  // Currently selected algorithm for this browser session (defaults to the
  // original app behavior, ML-KEM-512, so nothing breaks for existing users).
  private currentAlgorithm: Algorithm = 'ML-KEM-512';

  setAlgorithm(algorithm: Algorithm): void {
    this.currentAlgorithm = algorithm;
  }

  getAlgorithm(): Algorithm {
    return this.currentAlgorithm;
  }

  private quantumKeysStorageKey(algorithm: Algorithm): string {
    // Namespaced by user id, not just algorithm — otherwise switching
    // accounts in the same browser tab silently reuses the previous
    // user's cached keys (they'd look "already generated" even though
    // they belong to someone else entirely).
    const userId = this.currentUser()?.id ?? 'anonymous';
    return `${this.QUANTUM_KEYS_KEY}_${userId}_${algorithm}`;
  }

  async generateQuantumKeys(algorithm: Algorithm = this.currentAlgorithm): Promise<QuantumKeys | null> {
    const storage = this.getStorage();
    if (!storage) {
      console.log('Not in browser, skipping quantum key generation');
      return null;
    }

    // Check if we already have keys for this algorithm
    const existing = storage.getItem(this.quantumKeysStorageKey(algorithm));
    if (existing) {
      return JSON.parse(existing);
    }

    try {
      const headers = this.getAuthHeaders();
      const response = await fetch(`${API_URL}/quantum/generate-keys`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm }),
      });

      if (!response.ok) {
        throw new Error('Failed to generate quantum keys');
      }

      const keys = await response.json();

      storage.setItem(this.quantumKeysStorageKey(algorithm), JSON.stringify({
        publicKey: keys.publicKey,
        secretKey: keys.secretKey
      }));

      return keys;
    } catch (error) {
      console.error('Failed to generate quantum keys:', error);
      return null;
    }
  }

  getQuantumKeys(algorithm: Algorithm = this.currentAlgorithm): QuantumKeys | null {
    const storage = this.getStorage();
    if (!storage) return null;
    const raw = storage.getItem(this.quantumKeysStorageKey(algorithm));
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  // ==================== ML-DSA (DILITHIUM) SIGNATURE KEYS ====================
  // Currently selected signature algorithm — defaults to ML-DSA-44 (smallest
  // NIST security level), independent of the KEM algorithm selection above.
  private currentSigAlgorithm: SigAlgorithm = 'ML-DSA-44';

  setSigAlgorithm(algorithm: SigAlgorithm): void {
    this.currentSigAlgorithm = algorithm;
  }

  getSigAlgorithm(): SigAlgorithm {
    return this.currentSigAlgorithm;
  }

  private sigKeysStorageKey(algorithm: SigAlgorithm): string {
    // Same reasoning as quantumKeysStorageKey — namespaced per user id.
    const userId = this.currentUser()?.id ?? 'anonymous';
    return `${this.SIG_KEYS_KEY}_${userId}_${algorithm}`;
  }

  async generateSigKeys(algorithm: SigAlgorithm = this.currentSigAlgorithm): Promise<QuantumKeys | null> {
    const storage = this.getStorage();
    if (!storage) return null;

    const existing = storage.getItem(this.sigKeysStorageKey(algorithm));
    if (existing) {
      return JSON.parse(existing);
    }

    try {
      const headers = this.getAuthHeaders();
      const response = await fetch(`${API_URL}/quantum/generate-sig-keys`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm }),
      });

      if (!response.ok) {
        throw new Error('Failed to generate signature keys');
      }

      const keys = await response.json();
      storage.setItem(this.sigKeysStorageKey(algorithm), JSON.stringify({
        publicKey: keys.publicKey,
        secretKey: keys.secretKey,
      }));
      return keys;
    } catch (error) {
      console.error('Failed to generate signature keys:', error);
      return null;
    }
  }

  // ==================== USER PUBLIC KEY ====================

  async getUserPublicKey(userId: number, algorithm: Algorithm = this.currentAlgorithm): Promise<string | null> {
    try {
      const headers = this.getAuthHeaders();
      const response = await fetch(`${API_URL}/quantum/public-key/${userId}?algorithm=${algorithm}`, {
        method: 'GET',
        headers,
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      return data.publicKey || null;
    } catch (error) {
      console.error('Failed to get user public key:', error);
      return null;
    }
  }

  // ==================== SHARED SECRET MANAGEMENT ====================

  async createSharedSecret(recipientPublicKey: string, algorithm: Algorithm = this.currentAlgorithm): Promise<{ ciphertext: string | null; sharedSecret: string } | null> {
    try {
      const headers = this.getAuthHeaders();
      const response = await fetch(`${API_URL}/quantum/create-secret`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipientPublicKey, algorithm }),
      });

      if (!response.ok) {
        throw new Error('Failed to create shared secret');
      }

      return response.json();
    } catch (error) {
      console.error('Failed to create shared secret:', error);
      return null;
    }
  }

  async initQuantumSession(recipientPublicKey: string, algorithm: Algorithm = this.currentAlgorithm): Promise<QuantumSession | null> {
    const result = await this.createSharedSecret(recipientPublicKey, algorithm);
    if (result) {
      return { sharedSecret: result.sharedSecret, ciphertext: result.ciphertext };
    }
    return null;
  }

  private sessionKey(userId: number, algorithm: Algorithm): string {
    return `${userId}_${algorithm}`;
  }

  // Namespaced per logged-in user, same reasoning as the key-storage
  // functions above — the sessions map otherwise gets shared across
  // whichever account happens to be logged in, causing a freshly logged
  // in user to silently inherit a previous account's established
  // sessions with other users.
  private quantumSessionsStorageKey(): string {
    const userId = this.currentUser()?.id ?? 'anonymous';
    return `${this.QUANTUM_SESSIONS_KEY}_${userId}`;
  }

  storeQuantumSession(userId: number, session: QuantumSession, algorithm: Algorithm = this.currentAlgorithm): void {
    const storage = this.getStorage();
    if (storage) {
      const sessions = this.getQuantumSessions();
      sessions.set(this.sessionKey(userId, algorithm), session);
      storage.setItem(this.quantumSessionsStorageKey(), JSON.stringify(Array.from(sessions.entries())));
    }
  }

  getQuantumSessions(): Map<string, QuantumSession> {
    const storage = this.getStorage();
    if (!storage) return new Map();
    const raw = storage.getItem(this.quantumSessionsStorageKey());
    if (!raw) return new Map();
    try {
      return new Map(JSON.parse(raw));
    } catch {
      return new Map();
    }
  }

  getSharedSecret(userId: number, algorithm: Algorithm = this.currentAlgorithm): string | null {
    const sessions = this.getQuantumSessions();
    const session = sessions.get(this.sessionKey(userId, algorithm));
    return session?.sharedSecret || null;
  }

  // Ensures a usable shared secret exists for chatting with otherUserId
  // under the given algorithm. Checks the local session cache first; if
  // missing (e.g. after a page reload, cleared storage, or a fresh
  // browser/tab), actively re-establishes the session by fetching the
  // other user's public key and re-deriving the secret via the backend.
  // This is the fallback path X25519 needs (no ciphertext to recover
  // from), and it also makes the ML-KEM paths more resilient.
  async ensureSharedSecret(otherUserId: number, algorithm: Algorithm = this.currentAlgorithm): Promise<string | null> {
    const cached = this.getSharedSecret(otherUserId, algorithm);
    if (cached) return cached;

    console.log(`No cached ${algorithm} session with user ${otherUserId} — re-establishing`);
    const publicKey = await this.getUserPublicKey(otherUserId, algorithm);
    if (!publicKey) {
      console.warn(`Cannot re-establish session: user ${otherUserId} has no ${algorithm} public key`);
      return null;
    }

    const session = await this.initQuantumSession(publicKey, algorithm);
    if (!session) return null;

    this.storeQuantumSession(otherUserId, session, algorithm);
    return session.sharedSecret;
  }

  async recoverSharedSecretFromCiphertext(ciphertext: string, algorithm: Algorithm = this.currentAlgorithm): Promise<string | null> {
    try {
      const headers = this.getAuthHeaders();
      const response = await fetch(`${API_URL}/quantum/recover-secret`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ciphertext, algorithm }),
      });

      if (!response.ok) {
        console.error('Failed to recover shared secret');
        return null;
      }

      const data = await response.json();
      return data.sharedSecret || null;
    } catch (error) {
      console.error('Failed to recover shared secret from ciphertext:', error);
      return null;
    }
  }

  // ==================== SENT MESSAGE KEY STORAGE ====================
  // Permanently store keys used to encrypt sent messages so they can be decrypted later

  private sentMessageKeysStorageKey(): string {
    const userId = this.currentUser()?.id ?? 'anonymous';
    return `${this.SENT_MESSAGE_KEYS_KEY}_${userId}`;
  }

  storeSentMessageKey(messageId: number, recipientId: number, sharedSecret: string): void {
    const storage = this.getStorage();
    if (storage) {
      try {
        const keys = this.getSentMessageKeys();
        const key = `${messageId}_${recipientId}`;
        keys[key] = sharedSecret;
        storage.setItem(this.sentMessageKeysStorageKey(), JSON.stringify(keys));
      } catch (error) {
        console.error('Failed to store sent message key:', error);
      }
    }
  }

  getSentMessageKey(messageId: number, recipientId: number): string | null {
    const storage = this.getStorage();
    if (!storage) return null;
    try {
      const keys = this.getSentMessageKeys();
      const key = `${messageId}_${recipientId}`;
      return keys[key] || null;
    } catch (error) {
      console.error('Failed to retrieve sent message key:', error);
      return null;
    }
  }

  private getSentMessageKeys(): Record<string, string> {
    const storage = this.getStorage();
    if (!storage) return {};
    try {
      const raw = storage.getItem(this.sentMessageKeysStorageKey());
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  }

  // ==================== AUTH METHODS ====================

  async register(user: UserRecord) {
    const response = await fetch(`${API_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(user),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error((data as any).message || `Registration failed (${response.status})`);
    }
    window.location.href = '/login';
  }

  async login(username: string, password: string) {
    const storage = this.getStorage();
    if (!storage) throw new Error('Storage unavailable');

    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error((data as any).message || 'Invalid username or password');
    }
    const { token, user } = await response.json();
    if (!token) throw new Error('Invalid server response: missing token');
    if (!user) throw new Error('Invalid server response: missing user data');

    storage.setItem(this.AUTH_TOKEN_KEY, token);
    storage.setItem(this.CURRENT_USER_KEY, JSON.stringify(user));
    
    // Generate quantum keys after successful login (only in browser)
    if (isPlatformBrowser(this.platformId)) {
      try {
        await this.generateQuantumKeys();
        console.log('✅ Quantum keys generated and stored');
      } catch (error) {
        console.error('Failed to generate quantum keys:', error);
      }
    }
    
    window.location.href = '/home';
  }

  logout() {
    const storage = this.getStorage();
    storage?.removeItem(this.AUTH_TOKEN_KEY);
    storage?.removeItem(this.CURRENT_USER_KEY);
    storage?.removeItem(this.QUANTUM_KEYS_KEY);
    storage?.removeItem(this.QUANTUM_SESSIONS_KEY);
  }

  isAuthenticated(): boolean {
    const storage = this.getStorage();
    return !!storage?.getItem(this.AUTH_TOKEN_KEY);
  }

  currentUser(): UserRecord | null {
    const storage = this.getStorage();
    if (!storage) return null;
    const raw = storage.getItem(this.CURRENT_USER_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as UserRecord;
    } catch {
      return null;
    }
  }

  getAuthHeaders(): HeadersInit {
    const storage = this.getStorage();
    if (!storage) return {};
    const token = storage.getItem(this.AUTH_TOKEN_KEY);
    if (!token) return {};
    return { Authorization: `Bearer ${token}` };
  }
}