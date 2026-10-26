// api/src/schema.ts
import { index, int, sqliteTable, text, unique } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
    id: int().primaryKey({ autoIncrement: true }),
    username: text().notNull(),
    password: text().notNull(),
    firstName: text().notNull(),
    lastName: text().notNull(),
    createdAt: text().notNull().default(new Date().toISOString()),
});

export const messages = sqliteTable("messages", {
    id: int().primaryKey({ autoIncrement: true }),
    senderId: int().notNull().references(() => users.id),
    receiverId: int().notNull().references(() => users.id),
    content: text().notNull(),
    quantumCiphertext: text(), // Store Kyber ciphertext for shared secret recovery
    algorithm: text().notNull().default('ML-KEM-512'), // which KEM/classical algorithm secured this message
    signature: text(), // ML-DSA signature over the content, base64
    sigAlgorithm: text(), // which ML-DSA variant produced the signature (null if unsigned)
    createdAt: text().notNull().default(new Date().toISOString()),
}, (table) => ({
    senderReceiverCreatedAtIdx: index("messages_sender_receiver_created_at_idx")
        .on(table.senderId, table.receiverId, table.createdAt),
    receiverSenderCreatedAtIdx: index("messages_receiver_sender_created_at_idx")
        .on(table.receiverId, table.senderId, table.createdAt),
}));

export const quantumKeys = sqliteTable("quantum_keys", {
    id: int().primaryKey({ autoIncrement: true }),
    user_id: int().notNull().references(() => users.id, { onDelete: 'cascade' }),
    algorithm: text().notNull().default('ML-KEM-512'), // e.g. ML-KEM-512, ML-KEM-768, ML-KEM-1024, X25519
    public_key: text().notNull(),
    secret_key: text().notNull(),
    created_at: text().notNull().default(new Date().toISOString()),
}, (table) => ({
    userAlgorithmUnique: unique().on(table.user_id, table.algorithm),
}));

export const quantumSigKeys = sqliteTable("quantum_sig_keys", {
    id: int().primaryKey({ autoIncrement: true }),
    user_id: int().notNull().references(() => users.id, { onDelete: 'cascade' }),
    algorithm: text().notNull().default('ML-DSA-44'), // ML-DSA-44, ML-DSA-65, ML-DSA-87
    public_key: text().notNull(),
    secret_key: text().notNull(),
    created_at: text().notNull().default(new Date().toISOString()),
}, (table) => ({
    userAlgorithmUnique: unique().on(table.user_id, table.algorithm),
}));