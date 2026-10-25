import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

// ML-DSA (Dilithium) — NIST-standardized post-quantum digital signature
// algorithm. Used here to sign message ciphertext so the recipient can
// verify both who sent it and that it wasn't tampered with in transit —
// this is a separate security property (authenticity/integrity) from
// ML-KEM, which only provides confidentiality.

export type SigAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export const SUPPORTED_SIG_ALGORITHMS: SigAlgorithm[] = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

const SIG_MAP = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
} as const;

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
    try {
      const sig = SIG_MAP[resolveAlgorithm(algorithm)];
      const signature = Buffer.from(signatureBase64, 'base64');
      const publicKey = Buffer.from(publicKeyBase64, 'base64');
      const messageBytes = new TextEncoder().encode(message);
      // @noble/post-quantum v0.6+ signature: verify(sig, msg, publicKey)
      return sig.verify(signature, messageBytes, publicKey);
    } catch (error) {
      console.error('Signature verification error:', error);
      return false;
    }
  }
}

export const dilithiumService = new DilithiumService();
