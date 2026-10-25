import { x25519 } from '@noble/curves/ed25519.js';

// Classical (non-PQC) baseline for comparison purposes.
// Uses X25519 Diffie-Hellman instead of a KEM: both sides derive the
// same shared secret from their own private key + the other party's
// public key, so there is no "ciphertext" to transmit like with ML-KEM.

export class ClassicalService {
  generateKeypair(): { publicKey: string; secretKey: string } {
    const secretKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.getPublicKey(secretKey);
    return {
      publicKey: Buffer.from(publicKey).toString('base64'),
      secretKey: Buffer.from(secretKey).toString('base64'),
    };
  }

  deriveSharedSecret(theirPublicKeyBase64: string, mySecretKeyBase64: string): string {
    const theirPublicKey = Buffer.from(theirPublicKeyBase64, 'base64');
    const mySecretKey = Buffer.from(mySecretKeyBase64, 'base64');
    const sharedSecret = x25519.getSharedSecret(mySecretKey, theirPublicKey);
    return Buffer.from(sharedSecret).toString('base64');
  }
}

export const classicalService = new ClassicalService();
