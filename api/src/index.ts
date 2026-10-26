import 'dotenv/config';
import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/libsql';
import { jwt, sign } from 'hono/jwt';
import type { JwtVariables } from 'hono/jwt';
import { messages, users, quantumKeys, quantumSigKeys } from './schema';
import { cors } from 'hono/cors';
import { eq, and, or, not, asc } from 'drizzle-orm';
import { kyberService, SUPPORTED_ALGORITHMS } from './encryption/kyber.service';
import { classicalService } from './encryption/classical.service';
import { dilithiumService, SUPPORTED_SIG_ALGORITHMS } from './encryption/dilithium.service';
import { encryptForStorage, decryptFromStorage } from './encryption/keyStorage';

const ALL_ALGORITHMS = [...SUPPORTED_ALGORITHMS, 'X25519'] as const;
type Algorithm = typeof ALL_ALGORITHMS[number];

function normalizeAlgorithm(alg: unknown): Algorithm {
  return ALL_ALGORITHMS.includes(alg as Algorithm) ? (alg as Algorithm) : 'ML-KEM-512';
}

type SigAlgorithm = typeof SUPPORTED_SIG_ALGORITHMS[number];

function normalizeSigAlgorithm(alg: unknown): SigAlgorithm {
  return SUPPORTED_SIG_ALGORITHMS.includes(alg as SigAlgorithm) ? (alg as SigAlgorithm) : 'ML-DSA-44';
}

type Variables = JwtVariables;

export const db = drizzle(process.env.DB_FILE_NAME!);

const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_ALGORITHM = 'HS256';

const app = new Hono<{ Variables: Variables }>();
app.use('/*', cors());

// ==================== PUBLIC ROUTES ====================

app.post('/register', async (c) => {
  const { firstName, lastName, username, password } = await c.req.json();
  if (!firstName || !lastName || !username || !password) {
    return c.json({ message: 'All fields are required' }, 400);
  }
  const existing = await db.select({ id: users.id }).from(users).where(eq(users.username, username)).get();
  if (existing) {
    return c.json({ message: 'Username already taken' }, 409);
  }
  await db.insert(users).values({
    firstName,
    lastName,
    username,
    password: await Bun.password.hash(password)
  }).run();
  return c.json({ message: 'User registered successfully!' });
});

app.post('/login', async (c) => {
  const { username, password } = await c.req.json();
  if (!username || !password) {
    return c.json({ message: 'Username and password are required' }, 400);
  }
  const user = await db.select().from(users).where(eq(users.username, username)).get();
  if (!user) {
    return c.json({ message: 'Invalid username or password' }, 401);
  }
  const valid = await Bun.password.verify(password, user.password);
  if (!valid) {
    return c.json({ message: 'Invalid username or password' }, 401);
  }
  const token = await sign(
    { sub: String(user.id), exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 },
    JWT_SECRET,
  );
  return c.json({
    token,
    user: { id: user.id, firstName: user.firstName, lastName: user.lastName, username: user.username },
  });
});

// ==================== PROTECTED ROUTES ====================

app.use('/users/*', jwt({ secret: JWT_SECRET, alg: JWT_ALGORITHM }));
app.use('/quantum/*', jwt({ secret: JWT_SECRET, alg: JWT_ALGORITHM }));

app.get('/users', async (c) => {
  const payload = c.get('jwtPayload');
  const currentUserId = Number(payload.sub);
  const records = await db
    .select({ id: users.id, firstName: users.firstName, lastName: users.lastName, username: users.username })
    .from(users)
    .where(not(eq(users.id, currentUserId)))
    .all();
  return c.json(records);
});

app.get('/users/:id/messages', async (c) => {
  const payload = c.get('jwtPayload');
  const currentUserId = Number(payload.sub);
  const userId = Number(c.req.param('id'));
  const records = await db
    .select()
    .from(messages)
    .where(
      or(
        and(eq(messages.senderId, currentUserId), eq(messages.receiverId, userId)),
        and(eq(messages.senderId, userId), eq(messages.receiverId, currentUserId)),
      ),
    )
    .orderBy(asc(messages.createdAt))
    .all();

  // Reuse the sender's public-key lookup for messages signed by the same
  // user/algorithm during this request, instead of querying once per message.
  const senderKeyCache = new Map<string, Promise<{ public_key: string } | undefined>>();

  // Verify each message's ML-DSA signature (if present) using the sender's
  // stored public key, so the client can show an authenticity indicator.
  const withVerification = await Promise.all(records.map(async (msg) => {
    if (!msg.signature || !msg.sigAlgorithm) {
      return { ...msg, signatureValid: null }; // unsigned message (e.g. sent before this feature, or signing failed)
    }
    const cacheKey = `${msg.senderId}:${msg.sigAlgorithm}`;
    let senderSigKeyPromise = senderKeyCache.get(cacheKey);
    if (!senderSigKeyPromise) {
      senderSigKeyPromise = db.select({ public_key: quantumSigKeys.public_key })
        .from(quantumSigKeys)
        .where(and(eq(quantumSigKeys.user_id, msg.senderId), eq(quantumSigKeys.algorithm, msg.sigAlgorithm)))
        .get();
      senderKeyCache.set(cacheKey, senderSigKeyPromise);
    }
    const senderSigKey = await senderSigKeyPromise;
    if (!senderSigKey) {
      return { ...msg, signatureValid: null };
    }
    const signatureValid = dilithiumService.verify(msg.content, msg.signature, senderSigKey.public_key, msg.sigAlgorithm);
    return { ...msg, signatureValid };
  }));

  return c.json(withVerification);
});

app.post('/users/:id/messages', async (c) => {
  const payload = c.get('jwtPayload');
  const currentUserId = Number(payload.sub);
  const userId = Number(c.req.param('id'));
  const { content, quantumCiphertext, algorithm, sigAlgorithm: rawSigAlgorithm } = await c.req.json();
  if (!content?.trim()) {
    return c.json({ message: 'Message content is required' }, 400);
  }

  // Sign the (already encrypted) content with the sender's ML-DSA key, if
  // they have one, so the recipient can verify authenticity + integrity.
  let signature: string | null = null;
  let sigAlgorithm: string | null = null;
  if (rawSigAlgorithm) {
    const normalizedSigAlg = normalizeSigAlgorithm(rawSigAlgorithm);
    const senderSigKey = await db.select({ secret_key: quantumSigKeys.secret_key })
      .from(quantumSigKeys)
      .where(and(eq(quantumSigKeys.user_id, currentUserId), eq(quantumSigKeys.algorithm, normalizedSigAlg)))
      .get();
    if (senderSigKey) {
      const decryptedSecretKey = decryptFromStorage(senderSigKey.secret_key);
      signature = dilithiumService.sign(content, decryptedSecretKey, normalizedSigAlg);
      sigAlgorithm = normalizedSigAlg;
    }
  }

  const result = await db
    .insert(messages)
    .values({ 
      senderId: currentUserId, 
      receiverId: userId, 
      content, 
      quantumCiphertext: quantumCiphertext || null,
      algorithm: normalizeAlgorithm(algorithm),
      signature,
      sigAlgorithm,
      createdAt: new Date().toISOString() 
    })
    .run();
  return c.json({ message: 'Message sent successfully!', messageId: Number(result.lastInsertRowid) });
});

// ==================== QUANTUM-SAFE CRYPTO ROUTES ====================

/**
 * Generate Kyber512 quantum-safe keypair for the authenticated user
 * POST /quantum/generate-keys
 */
app.post('/quantum/generate-keys', async (c) => {
  const payload = c.get('jwtPayload');
  const userId = Number(payload.sub);
  const body = await c.req.json().catch(() => ({}));
  const algorithm = normalizeAlgorithm(body?.algorithm);

  console.log(`Generating ${algorithm} keys for user: ${userId}`);

  // Check if user already has keys for this specific algorithm
  const existing = await db.select().from(quantumKeys)
    .where(and(eq(quantumKeys.user_id, userId), eq(quantumKeys.algorithm, algorithm)))
    .get();

  if (existing) {
    console.log(`User ${userId} already has ${algorithm} keys`);
    return c.json({ 
      publicKey: existing.public_key,
      secretKey: decryptFromStorage(existing.secret_key),
      algorithm,
      message: 'Using existing quantum keys'
    });
  }

  // Generate a new keypair for the requested algorithm
  const keypair = algorithm === 'X25519'
    ? classicalService.generateKeypair()
    : kyberService.generateKeypair(algorithm);

  await db.insert(quantumKeys).values({
    user_id: userId,
    algorithm,
    public_key: keypair.publicKey,
    secret_key: encryptForStorage(keypair.secretKey)
  }).run();

  console.log(`${algorithm} keys saved for user ${userId}`);

  return c.json({ 
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
    algorithm,
    message: 'New quantum keys generated and stored'
  });
});

/**
 * List all algorithms this user currently has keys for
 * GET /quantum/my-algorithms
 */
app.get('/quantum/my-algorithms', async (c) => {
  const payload = c.get('jwtPayload');
  const userId = Number(payload.sub);
  const rows = await db.select({ algorithm: quantumKeys.algorithm })
    .from(quantumKeys)
    .where(eq(quantumKeys.user_id, userId))
    .all();
  return c.json({ algorithms: rows.map(r => r.algorithm), supported: ALL_ALGORITHMS });
});

/**
 * Generate an ML-DSA (Dilithium) signature keypair for the authenticated user
 * POST /quantum/generate-sig-keys
 */
app.post('/quantum/generate-sig-keys', async (c) => {
  const payload = c.get('jwtPayload');
  const userId = Number(payload.sub);
  const body = await c.req.json().catch(() => ({}));
  const algorithm = normalizeSigAlgorithm(body?.algorithm);

  console.log(`Generating ${algorithm} signature keys for user: ${userId}`);

  const existing = await db.select().from(quantumSigKeys)
    .where(and(eq(quantumSigKeys.user_id, userId), eq(quantumSigKeys.algorithm, algorithm)))
    .get();

  if (existing) {
    return c.json({
      publicKey: existing.public_key,
      secretKey: decryptFromStorage(existing.secret_key),
      algorithm,
      message: 'Using existing signature keys'
    });
  }

  const keypair = dilithiumService.generateKeypair(algorithm);

  await db.insert(quantumSigKeys).values({
    user_id: userId,
    algorithm,
    public_key: keypair.publicKey,
    secret_key: encryptForStorage(keypair.secretKey)
  }).run();

  console.log(`${algorithm} signature keys saved for user ${userId}`);

  return c.json({
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
    algorithm,
    message: 'New signature keys generated and stored'
  });
});

/**
 * Get another user's ML-DSA public key from database
 * GET /quantum/sig-public-key/:userId
 */
app.get('/quantum/sig-public-key/:userId', async (c) => {
  const targetUserId = Number(c.req.param('userId'));
  const algorithm = normalizeSigAlgorithm(c.req.query('algorithm'));

  const keyRecord = await db.select({
    public_key: quantumSigKeys.public_key
  }).from(quantumSigKeys)
    .where(and(eq(quantumSigKeys.user_id, targetUserId), eq(quantumSigKeys.algorithm, algorithm)))
    .get();

  if (!keyRecord) {
    return c.json({
      error: `User has not generated ${algorithm} signature keys yet`,
      hasKeys: false
    }, 404);
  }

  return c.json({
    publicKey: keyRecord.public_key,
    algorithm,
    hasKeys: true
  });
});

/**
 * Get another user's public key from database
 * GET /quantum/public-key/:userId
 */
app.get('/quantum/public-key/:userId', async (c) => {
  const targetUserId = Number(c.req.param('userId'));
  const algorithm = normalizeAlgorithm(c.req.query('algorithm'));

  const keyRecord = await db.select({ 
    public_key: quantumKeys.public_key
  }).from(quantumKeys)
    .where(and(eq(quantumKeys.user_id, targetUserId), eq(quantumKeys.algorithm, algorithm)))
    .get();
  
  if (!keyRecord) {
    return c.json({ 
      error: `User has not generated ${algorithm} keys yet`,
      hasKeys: false 
    }, 404);
  }
  
  return c.json({ 
    publicKey: keyRecord.public_key,
    algorithm,
    hasKeys: true 
  });
});

/**
 * Create a shared secret using recipient's public key
 * POST /quantum/create-secret
 */
app.post('/quantum/create-secret', async (c) => {
  const payload = c.get('jwtPayload');
  const userId = Number(payload.sub);
  const { recipientPublicKey, algorithm: rawAlgorithm } = await c.req.json();
  const algorithm = normalizeAlgorithm(rawAlgorithm);

  if (!recipientPublicKey) {
    return c.json({ message: 'Recipient public key is required' }, 400);
  }

  // X25519 is Diffie-Hellman, not a KEM: no ciphertext is produced,
  // both sides derive the same secret from their own keys.
  if (algorithm === 'X25519') {
    const myKeys = await db.select().from(quantumKeys)
      .where(and(eq(quantumKeys.user_id, userId), eq(quantumKeys.algorithm, 'X25519')))
      .get();
    if (!myKeys) {
      return c.json({ message: 'Generate X25519 keys first' }, 404);
    }
    const sharedSecret = classicalService.deriveSharedSecret(recipientPublicKey, decryptFromStorage(myKeys.secret_key));
    return c.json({ ciphertext: null, sharedSecret, algorithm });
  }

  const { ciphertext, sharedSecret } = kyberService.encapsulateSecret(recipientPublicKey, algorithm);

  return c.json({ 
    ciphertext,
    sharedSecret,
    algorithm
  });
});

/**
 * Recover shared secret using ciphertext and your secret key
 * POST /quantum/recover-secret
 */
app.post('/quantum/recover-secret', async (c) => {
  const payload = c.get('jwtPayload');
  const userId = Number(payload.sub);
  const { ciphertext, algorithm: rawAlgorithm } = await c.req.json();
  const algorithm = normalizeAlgorithm(rawAlgorithm);

  if (!ciphertext) {
    return c.json({ message: 'Ciphertext is required' }, 400);
  }

  // Retrieve the user's secret key for this specific algorithm
  const keyRecord = await db.select({
    secret_key: quantumKeys.secret_key
  }).from(quantumKeys)
    .where(and(eq(quantumKeys.user_id, userId), eq(quantumKeys.algorithm, algorithm)))
    .get();

  if (!keyRecord) {
    return c.json({ 
      message: `User has not generated ${algorithm} keys yet. Please generate keys first.`,
      error: 'NO_QUANTUM_KEYS'
    }, 404);
  }

  const sharedSecret = kyberService.decapsulateSecret(ciphertext, decryptFromStorage(keyRecord.secret_key), algorithm);

  return c.json({ sharedSecret, algorithm });
});

/**
 * Check if user has quantum keys
 * GET /quantum/status
 */
app.get('/quantum/status', async (c) => {
  const payload = c.get('jwtPayload');
  const userId = Number(payload.sub);
  
  const keys = await db.select({ id: quantumKeys.id }).from(quantumKeys).where(eq(quantumKeys.user_id, userId)).get();
  
  return c.json({ 
    hasQuantumKeys: !!keys,
    message: !!keys ? 'Quantum keys ready' : 'Generate quantum keys first'
  });
});

/**
 * Health check endpoint
 * GET /health
 */
app.get('/health', (c) => {
  return c.json({ 
    status: 'healthy',
    quantumEnabled: true,
    supportedAlgorithms: ALL_ALGORITHMS,
    supportedSigAlgorithms: SUPPORTED_SIG_ALGORITHMS,
    timestamp: new Date().toISOString()
  });
});

export default app;