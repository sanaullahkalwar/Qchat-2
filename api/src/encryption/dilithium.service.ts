import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { createPublicKey, verify as nativeVerify, type KeyObject } from 'crypto';

// ML-DSA (Dilithium) — NIST-standardized post-quantum digital signature
// algorithm. Used here to sign message ciphertext so the recipient can
// verify both who sent it and that it wasn't tampered with in transit —
// this is a separate security property (authenticity/integrity) from
// ML-KEM, which only provides confidentiality.
//
// Verification runs on the runtime's native ML-DSA (Bun/BoringSSL) because
// it is ~30x faster than the pure-JS implementation; signatures are
// interoperable between the two. If native verification throws for any
// reason, we fall back to the pure-JS implementation.

export type SigAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export const SUPPORTED_SIG_ALGORITHMS: SigAlgorithm[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

const SIG_MAP = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
} as const;

// --- minimal DER helpers to wrap a raw ML-DSA public key as SPKI ---
const derLen = (n: number): Buffer =>
  n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]);

const der = (tag: number, ...parts: Buffer[]): Buffer => {
  const content = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
};

const OID_SUFFIX: Record<SigAlgorithm, string> = {
  'ML-DSA-44': '11',
  'ML-DSA-65': '12',
  'ML-DSA-87': '13',
};

const ALG_ID: Record<SigAlgorithm, Buffer> = {
  'ML-DSA-44': der(0x30, Buffer.from('06096086480165030403' + OID_SUFFIX['ML-DSA-44'], 'hex')),
  'ML-DSA-65': der(0x30, Buffer.from('06096086480165030403' + OID_SUFFIX['ML-DSA-65'], 'hex')),
  'ML-DSA-87': der(0x30, Buffer.from('06096086480165030403' + OID_SUFFIX['ML-DSA-87'], 'hex')),
};

const publicKeyCache = new Map<string, KeyObject>();
const PUBLIC_KEY_CACHE_MAX = 1000;

function nativePublicKey(alg: SigAlgorithm, publicKeyBase64: string): KeyObject {
  const cacheKey = alg + ':' + publicKeyBase64;
  let key = publicKeyCache.get(cacheKey);
  if (!key) {
    if (publicKeyCache.size >= PUBLIC_KEY_CACHE_MAX) publicKeyCache.clear();
    const raw = Buffer.from(publicKeyBase64, 'base64');
    key = createPublicKey({
      key: der(0x30, ALG_ID[alg], der(0x03, Buffer.from([0]), raw)),
      format: 'der',
      type: 'spki',
    });
    publicKeyCache.set(cacheKey, key);
  }
  return key;
}

function resolveAlgorithm(algorithm?: string): SigAlgorithm {
  if (algorithm && SUPPORTED_SIG_ALGORITHMS.includes(algorithm as SigAlgorithm)) {
    return algorithm as SigAlgorithm;
  }
  return 'ML-DSA-44'; // default — smallest/fastest NIST security level
}

export class DilithiumService {
  generateKeypair(algorithm?: string): { publicKey: string; secretKey: string } {
    const sig = SIG_MAP[resolveAlgorithm(algorithm)];
    const keys = sig.keygen();
    return {
      publicKey: Buffer.from(keys.publicKey).toString('base64'),
      secretKey: Buffer.from(keys.secretKey).toString('base64'),
    };
  }

  sign(message: string, secretKeyBase64: string, algorithm?: string): string {
    const sig = SIG_MAP[resolveAlgorithm(algorithm)];
    const secretKey = Buffer.from(secretKeyBase64, 'base64');
    const messageBytes = new TextEncoder().encode(message);
    // @noble/post-quantum v0.6+ signature: sign(msg, secretKey)
    const signature = sig.sign(messageBytes, secretKey);
    return Buffer.from(signature).toString('base64');
  }

  verify(message: string, signatureBase64: string, publicKeyBase64: string, algorithm?: string): boolean {
    const algName = resolveAlgorithm(algorithm);
    const messageBytes = new TextEncoder().encode(message);
    const signature = Buffer.from(signatureBase64, 'base64');
    try {
      return nativeVerify(null, messageBytes, nativePublicKey(algName, publicKeyBase64), signature);
    } catch (nativeError) {
      console.warn('Native ML-DSA verify failed, falling back to noble:', (nativeError as Error).message);
      try {
        const publicKey = Buffer.from(publicKeyBase64, 'base64');
        // @noble/post-quantum v0.6+ signature: verify(sig, msg, publicKey)
        return SIG_MAP[algName].verify(signature, messageBytes, publicKey);
      } catch (error) {
        console.error('Signature verification error:', error);
        return false;
      }
    }
  }
}

export const dilithiumService = new DilithiumService();
