import {
  Component,
  OnInit,
  OnDestroy,
  ViewChild,
  ElementRef,
  PLATFORM_ID,
  ChangeDetectorRef,
  inject,
} from '@angular/core';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Auth, UserRecord, Algorithm, SUPPORTED_ALGORITHMS, SigAlgorithm, SUPPORTED_SIG_ALGORITHMS } from '../../services/auth';
import { API_URL } from '../../../environment';
import { MessageService } from 'primeng/api';
import { ToastModule } from 'primeng/toast';


interface UserType {
  id: number;
  firstName: string;
  lastName: string;
}
interface Message {
  id?: number;
  senderId: number;
  receiverId: number;
  content: string;
  createdAt: string;
  isEncrypted?: boolean;
  quantumCiphertext?: string;
  algorithm?: Algorithm;
  signature?: string;
  sigAlgorithm?: SigAlgorithm;
  signatureValid?: boolean | null;
}

@Component({
  selector: 'app-home',
  imports: [
    CommonModule,
    FormsModule,
    ToastModule,
  ],
  templateUrl: './home.html',
  styleUrl: './home.scss',
  providers: [MessageService],
})
export class Home implements OnInit, OnDestroy {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly auth = inject(Auth);
  private readonly messageService = inject(MessageService);

  users: UserType[] = [];
  selectedUser: number | null = null;
  activeOptionIndex = -1;
  isPopupOpen = false;

  allMessages: Message[] = [];
  currentUser: UserRecord | null = null;
  messageText = '';
  private intervalId: any;
  private isLoadingMessages = false;
  private readonly decryptedMessageCache = new Map<number, {
    encryptedContent: string;
    quantumCiphertext?: string;
    algorithm?: Algorithm;
    content: string;
    isEncrypted: boolean;
  }>();
  
  quantumReady: Map<number, boolean> = new Map();

  // Algorithm selection for testing/benchmarking different PQC/classical schemes
  readonly availableAlgorithms: Algorithm[] = SUPPORTED_ALGORITHMS;
  selectedAlgorithm: Algorithm = 'ML-KEM-512';

  readonly availableSigAlgorithms: SigAlgorithm[] = SUPPORTED_SIG_ALGORITHMS;
  selectedSigAlgorithm: SigAlgorithm = 'ML-DSA-44';
  sigKeysReady = false;

  @ViewChild('messagesContainer') messagesContainer!: ElementRef;

  async ngOnInit() {
    this.currentUser = this.auth.currentUser();
    await this.ensureQuantumKeys();
    await this.loadUsers();
    if (this.selectedUser) {
      await this.initQuantumSessionForUser(this.selectedUser);
      await this.loadMessages();
    }
    if (isPlatformBrowser(this.platformId)) {
      this.startTimer();
    }
  }

  async ensureQuantumKeys() {
    try {
      const keys = await this.auth.generateQuantumKeys(this.selectedAlgorithm);
      if (keys) {
        console.log('Quantum keys ready for user:', this.currentUser?.username);
      } else {
        console.log('Could not generate quantum keys');
      }
    } catch (error) {
      console.error('Failed to get quantum keys:', error);
    }

    try {
      const sigKeys = await this.auth.generateSigKeys(this.selectedSigAlgorithm);
      this.sigKeysReady = !!sigKeys;
      if (sigKeys) {
        console.log('Signature keys ready for user:', this.currentUser?.username);
      }
    } catch (error) {
      console.error('Failed to get signature keys:', error);
      this.sigKeysReady = false;
    }
  }

  async initQuantumSessionForUser(userId: number) {
    try {
      let sharedSecret = this.auth.getSharedSecret(userId, this.selectedAlgorithm);
      if (sharedSecret) {
        this.quantumReady.set(userId, true);
        console.log(`${this.selectedAlgorithm} session already exists for user ${userId}`);
        return true;
      }

      const publicKey = await this.auth.getUserPublicKey(userId, this.selectedAlgorithm);
      if (!publicKey) {
        this.quantumReady.set(userId, false);
        console.log(`User ${userId} doesn't have ${this.selectedAlgorithm} keys yet`);
        return false;
      }

      const session = await this.auth.initQuantumSession(publicKey, this.selectedAlgorithm);
      if (session) {
        this.auth.storeQuantumSession(userId, session, this.selectedAlgorithm);
        this.quantumReady.set(userId, true);
        console.log(`${this.selectedAlgorithm} session established with user ${userId}`);
        this.messageService.add({ 
          severity: 'success', 
          summary: 'Quantum Secure', 
          detail: `${this.selectedAlgorithm} encryption active for this chat!` 
        });
        return true;
      }

      this.quantumReady.set(userId, false);
      return false;
    } catch (error) {
      console.error('Failed to initialize quantum session:', error);
      this.quantumReady.set(userId, false);
      return false;
    }
  }

  // Called when the user picks a different algorithm from the dropdown.
  // Re-establishes the session with the currently selected chat partner
  // using the newly chosen algorithm.
  async onAlgorithmChange(algorithm: Algorithm) {
    this.selectedAlgorithm = algorithm;
    this.auth.setAlgorithm(algorithm);
    await this.ensureQuantumKeys();
    if (this.selectedUser) {
      await this.initQuantumSessionForUser(this.selectedUser);
      await this.loadMessages();
    }
  }

  // Called when the user picks a different ML-DSA signature algorithm.
  // Unlike KEM algorithm changes, this doesn't need a fresh session with
  // the chat partner (signing is per-user, not per-conversation) — it
  // just needs a keypair for the newly selected variant, generated once
  // and reused after that (same pattern as ensureQuantumKeys).
  async onSigAlgorithmChange(sigAlgorithm: SigAlgorithm) {
    this.selectedSigAlgorithm = sigAlgorithm;
    this.auth.setSigAlgorithm(sigAlgorithm);
    try {
      const sigKeys = await this.auth.generateSigKeys(sigAlgorithm);
      this.sigKeysReady = !!sigKeys;
      if (sigKeys) {
        console.log(`${sigAlgorithm} signature keys ready for user:`, this.currentUser?.username);
      }
    } catch (error) {
      console.error('Failed to get signature keys:', error);
      this.sigKeysReady = false;
    }
    // Reload messages so already-visible messages re-render with correct
    // badges if the selected algorithm changes which key would be used
    // for any NEW outgoing messages (existing messages' badges are based
    // on the algorithm actually used to sign them, read from each
    // message's own sigAlgorithm field — this reload just refreshes the
    // view, it does not re-sign anything already sent).
    if (this.selectedUser) {
      await this.loadMessages();
    }
  }

  async loadUsers() {
    try {
      const response = await fetch(`${API_URL}/users`, {
        headers: this.auth.getAuthHeaders(),
      });
      if (!response.ok) {
        this.messageService.add({ severity: 'error', summary: 'Error', detail: 'Failed to load users' });
        return;
      }
      this.users = (await response.json()) as UserType[];
      this.selectedUser = this.users[0]?.id ?? null;
      this.activeOptionIndex = -1;
      
      for (const user of this.users) {
        const publicKey = await this.auth.getUserPublicKey(user.id, this.selectedAlgorithm);
        this.quantumReady.set(user.id, !!publicKey);
      }
    } catch {
      this.messageService.add({ severity: 'error', summary: 'Error', detail: 'Could not connect to server' });
    }
  }

  async loadMessages() {
    if (!this.selectedUser || this.isLoadingMessages) return;
    this.isLoadingMessages = true;
    try {
      const response = await fetch(`${API_URL}/users/${this.selectedUser}/messages`, {
        headers: this.auth.getAuthHeaders(),
      });
      if (!response.ok) return;
      const messages = (await response.json()) as Message[];
      
      for (const msg of messages) {
        const encryptedContent = msg.content;
        const cached = msg.id ? this.decryptedMessageCache.get(msg.id) : undefined;
        if (
          cached &&
          cached.encryptedContent === encryptedContent &&
          cached.quantumCiphertext === msg.quantumCiphertext &&
          cached.algorithm === msg.algorithm
        ) {
          msg.content = cached.content;
          msg.isEncrypted = cached.isEncrypted;
          continue;
        }

        let displayContent = msg.content;
        let isEncrypted = false;
        
        // Check if content looks like Base64 (encrypted) or has quantumCiphertext
        const looksEncrypted = this.isBase64String(msg.content) && msg.content.length > 20;
        const hasQuantumData = !!msg.quantumCiphertext;
        
        if (looksEncrypted || hasQuantumData) {
          try {
            let sharedSecret: string | null = null;
            
            const msgAlgorithm: Algorithm = (msg as any).algorithm || this.selectedAlgorithm;

            if (this.isSentByCurrentUser(msg)) {
              // I sent this message - get stored key or session secret
              sharedSecret = this.auth.getSentMessageKey(msg.id!, this.selectedUser);
              
              if (!sharedSecret) {
                sharedSecret = await this.auth.ensureSharedSecret(this.selectedUser, msgAlgorithm);
                console.log(`Decrypting sent message ${msg.id} using re-established session secret`);
              } else {
                console.log(`Decrypting sent message ${msg.id} using stored key`);
              }
            } else {
              // I received this message - recover secret from ciphertext
              if (msg.quantumCiphertext) {
                try {
                  sharedSecret = await this.auth.recoverSharedSecretFromCiphertext(msg.quantumCiphertext, msgAlgorithm);
                  console.log(`Recovered secret for received message ${msg.id}`);
                } catch (e) {
                  console.error(`Failed to recover secret for message ${msg.id}:`, e);
                }
              }
              
              // Fallback to session secret if recovery failed, or if this
              // algorithm has no ciphertext to recover from (X25519).
              // ensureSharedSecret actively re-establishes the session
              // with the sender if it's missing from the local cache.
              if (!sharedSecret) {
                sharedSecret = await this.auth.ensureSharedSecret(msg.senderId, msgAlgorithm);
                console.log(`Ensured session secret for received message ${msg.id}`);
              }
            }
            
            if (sharedSecret) {
              try {
                displayContent = await this.auth.decryptMessage(msg.content, sharedSecret);
                isEncrypted = true;
                console.log(`Message ${msg.id} decrypted successfully`);
              } catch (decryptError) {
                console.error(`Decryption failed for message ${msg.id}:`, decryptError);
                displayContent = '[Decryption failed - key mismatch]';
                isEncrypted = true;
              }
            } else {
              displayContent = '[Unable to decrypt - no shared secret]';
              isEncrypted = true;
              console.warn(`No shared secret available for message ${msg.id}`);
            }
          } catch (error) {
            console.error('Decryption process error for message:', msg.id, error);
            displayContent = '[Failed to decrypt]';
            isEncrypted = true;
          }
        }
        
        msg.content = displayContent;
        msg.isEncrypted = isEncrypted;

        if (msg.id && isEncrypted) {
          this.decryptedMessageCache.set(msg.id, {
            encryptedContent,
            quantumCiphertext: msg.quantumCiphertext,
            algorithm: msg.algorithm,
            content: displayContent,
            isEncrypted,
          });
        }
      }
      
      this.allMessages = messages;
      this.cdr.detectChanges();
      setTimeout(() => this.scrollToBottom(), 0);
    } catch (error) {
      console.error('Error loading messages:', error);
    } finally {
      this.isLoadingMessages = false;
    }
  }

  async sendMessage() {
    if (!this.messageText.trim() || !this.selectedUser) return;
    
    let content = this.messageText.trim();
    this.messageText = '';
    
    const sharedSecret = await this.auth.ensureSharedSecret(this.selectedUser, this.selectedAlgorithm);
    const isQuantumActive = this.quantumReady.get(this.selectedUser) && sharedSecret;
    
    let messageToSend = content;
    let quantumCiphertextToSend: string | null = null;
    let encryptionKeyToStore: string | null = null;
    
    if (isQuantumActive && sharedSecret) {
      try {
        const encrypted = await this.auth.encryptMessage(content, sharedSecret);
        messageToSend = encrypted;
        encryptionKeyToStore = sharedSecret;
        
        // Get the ciphertext from the quantum session so receiver can recover the secret
        // (X25519 sessions have no ciphertext, since it's Diffie-Hellman, not a KEM)
        const sessions = this.auth.getQuantumSessions();
        const session = sessions.get(`${this.selectedUser}_${this.selectedAlgorithm}`);
        if (session?.ciphertext) {
          quantumCiphertextToSend = session.ciphertext;
        }
        
        console.log(`Message encrypted with ${this.selectedAlgorithm}`);
      } catch (error) {
        console.error('Encryption failed:', error);
        this.messageService.add({ 
          severity: 'warn', 
          summary: 'Encryption Failed', 
          detail: 'Sending message without encryption' 
        });
      }
    } else {
      console.log(`No quantum session, sending plain text`);
    }
    
    try {
      const payload: any = { content: messageToSend, algorithm: this.selectedAlgorithm };
      if (this.sigKeysReady) {
        payload.sigAlgorithm = this.selectedSigAlgorithm;
      }
      if (quantumCiphertextToSend) {
        payload.quantumCiphertext = quantumCiphertextToSend;
      }
      
      const response = await fetch(`${API_URL}/users/${this.selectedUser}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this.auth.getAuthHeaders() },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        this.messageService.add({ severity: 'error', summary: 'Error', detail: 'Failed to send message' });
        return;
      }
      
      // Store the encryption key for this sent message so we can decrypt it later
      const responseData = await response.json();
      if (responseData.messageId && encryptionKeyToStore) {
        this.auth.storeSentMessageKey(responseData.messageId, this.selectedUser, encryptionKeyToStore);
        console.log(`Stored encryption key for message ${responseData.messageId}`);
      }
      
      await this.loadMessages();
    } catch {
      this.messageService.add({ severity: 'error', summary: 'Error', detail: 'Failed to send message' });
    }
  }

  async switchUser() {
    this.allMessages = [];
    if (this.selectedUser) {
      await this.initQuantumSessionForUser(this.selectedUser);
    }
    this.loadMessages();
  }

  logout() {
    this.auth.logout();
    window.location.href = '/login';
  }

  isSentByCurrentUser(msg: Message): boolean {
    return msg.senderId === this.currentUser?.id;
  }

  isQuantumActive(): boolean {
    if (!this.selectedUser) return false;
    return this.quantumReady.get(this.selectedUser) || false;
  }

  // Helper method to check if a string is Base64 encoded
  private isBase64String(str: string): boolean {
    if (!str) return false;
    // Base64 pattern: alphanumeric + / + = at end (optional)
    const base64Regex = /^[A-Za-z0-9+/]+=*$/;
    return base64Regex.test(str);
  }

  get selectedUserName(): string {
    const u = this.users.find((u) => u.id === this.selectedUser);
    return u ? `${u.firstName} ${u.lastName}` : '';
  }

  get currentUserInitials(): string {
    if (!this.currentUser) return '?';
    return `${this.currentUser.firstName[0]}${this.currentUser.lastName[0]}`.toUpperCase();
  }

  get selectedUserInitials(): string {
    const u = this.users.find((u) => u.id === this.selectedUser);
    if (!u) return '?';
    return `${u.firstName[0]}${u.lastName[0]}`.toUpperCase();
  }

  formatTime(createdAt: string): string {
    return new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  get selectedUserLabel(): string {
    return this.selectedUserName || 'Select user';
  }

  get activeDescendantId(): string | null {
    return this.activeOptionIndex >= 0 && this.users[this.activeOptionIndex]
      ? this.optionId(this.activeOptionIndex)
      : null;
  }

  optionId(index: number): string {
    return `user-option-${index}`;
  }

  onComboboxFocus() {
    this.isPopupOpen = true;
  }

  onComboboxBlur() {
    setTimeout(() => {
      this.isPopupOpen = false;
    }, 150);
  }

  onComboboxKeydown(event: KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!this.users.length) return;
      this.activeOptionIndex =
        event.key === 'ArrowDown'
          ? (this.activeOptionIndex + 1) % this.users.length
          : this.activeOptionIndex <= 0
            ? this.users.length - 1
            : this.activeOptionIndex - 1;
      this.isPopupOpen = true;
      return;
    }
    if (event.key === 'Enter' && this.activeOptionIndex >= 0) {
      event.preventDefault();
      this.selectUser(this.users[this.activeOptionIndex]);
      return;
    }
    if (event.key === 'Escape') {
      this.isPopupOpen = false;
    }
  }

  async selectUser(user: UserType) {
    this.selectedUser = user.id;
    this.isPopupOpen = false;
    this.activeOptionIndex = -1;
    await this.initQuantumSessionForUser(user.id);
    this.switchUser();
  }

  get displayMessages(): Message[] {
    return this.allMessages;
  }

  private startTimer() {
    this.intervalId = setInterval(() => this.loadMessages(), 3000);
  }

  private scrollToBottom() {
    if (this.messagesContainer?.nativeElement) {
      this.messagesContainer.nativeElement.scrollTop = this.messagesContainer.nativeElement.scrollHeight;
    }
  }

  ngOnDestroy() {
    if (this.intervalId) clearInterval(this.intervalId);
  }
}