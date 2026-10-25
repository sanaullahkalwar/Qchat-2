import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// Encryption-at-rest wrapper for cryptographic secret keys stored in the
// database (ML-KEM decapsulation keys, ML-DSA signing keys, X25519 private
// keys). Without this, anyone with read access to quantum.db (a stolen
// backup, a misconfigured file permission, a compromised host) could read
// every user's private key material directly. Wrapping it with a separate
// server-side master key means the database file alone is not enough —
// the attacker also needs DB_ENCRYPTION_KEY, which is never stored in the
// database and should be kept out of source control (.env, gitignored).
//
// This does NOT eliminate the risk entirely (if the master key AND the
// database are both compromised, e.g. both sitting on the same host, the
// keys are still exposed) — see the thesis's Limitations section for the
// full discussion. It does meaningfully raise the bar against the most
// common real-world scenarios: a leaked database backup, an accidental
// public S3 bucket, a misconfigured file permission, or read-only SQL
// injection.

const MASTER_KEY_B64 = process.env.DB_ENCRYPTION_KEY;

if (!MASTER_KEY_B64) {
  throw new Error(
    'DB_ENCRYPTION_KEY environment variable is required to encrypt stored secret keys. ' +
    'Generate one with: openssl rand -base64 32'
  );
}

const MASTER_KEY = Buffer.from(MASTER_KEY_B64, 'base64');

if (MASTER_KEY.length !== 32) {
  throw new Error(
    'DB_ENCRYPTION_KEY must decode to exactly 32 bytes (256 bits). ' +
    'Generate one with: openssl rand -base64 32'
  );
}

const ALGO = 'aes-256-gcm';
const IV_LENGTH = 12;   // 96-bit nonce, standard for GCM
const TAG_LENGTH = 16;  // 128-bit authentication tag

/**
 * Encrypts a secret key value before storing it in the database.
 * Output format (base64): IV (12 bytes) || auth tag (16 bytes) || ciphertext
 */
export function encryptForStorage(plaintext: string): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGO, MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

/**
 * Decrypts a secret key value read back from the database.
 * Throws if the auth tag doesn't verify (tampered or wrong key) — this is
 * intentional: a failed decrypt should surface as an error, not silently
 * return garbage key material.
 */
export function decryptFromStorage(stored: string): string {
  const data = Buffer.from(stored, 'base64');
  const iv = data.subarray(0, IV_LENGTH);
  const authTag = data.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = data.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = createDecipheriv(ALGO, MASTER_KEY, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}
