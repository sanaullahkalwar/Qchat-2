import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

export type KemAlgorithm = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

export const SUPPORTED_ALGORITHMS: KemAlgorithm[] = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];

const KEM_MAP = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
} as const;

function resolveAlgorithm(algorithm?: string): KemAlgorithm {
  if (algorithm && SUPPORTED_ALGORITHMS.includes(algorithm as KemAlgorithm)) {
    return algorithm as KemAlgorithm;
  }
  return 'ML-KEM-512'; // default, keeps old behavior if no algorithm is passed
}

export class KyberService {
  generateKeypair(algorithm?: string): { publicKey: string; secretKey: string } {
    const kem = KEM_MAP[resolveAlgorithm(algorithm)];
    const keys = kem.keygen();
    return {
      publicKey: Buffer.from(keys.publicKey).toString('base64'),
      secretKey: Buffer.from(keys.secretKey).toString('base64'),
    };
  }

  encapsulateSecret(publicKeyBase64: string, algorithm?: string): { ciphertext: string; sharedSecret: string } {
    const kem = KEM_MAP[resolveAlgorithm(algorithm)];
    const publicKey = Buffer.from(publicKeyBase64, 'base64');
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
    return {
      ciphertext: Buffer.from(cipherText).toString('base64'),
      sharedSecret: Buffer.from(sharedSecret).toString('base64'),
    };
  }

  decapsulateSecret(ciphertextBase64: string, secretKeyBase64: string, algorithm?: string): string {
    const kem = KEM_MAP[resolveAlgorithm(algorithm)];
    const ciphertext = Buffer.from(ciphertextBase64, 'base64');
    const secretKey = Buffer.from(secretKeyBase64, 'base64');
    const sharedSecret = kem.decapsulate(ciphertext, secretKey);
    return Buffer.from(sharedSecret).toString('base64');
  }
}

export const kyberService = new KyberService();
