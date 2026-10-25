import { kyberService } from './src/encryption/kyber.service';

async function testKyber() {
    console.log("🔐 Testing Kyber512 Quantum-Safe Encryption");
    console.log("=".repeat(50));
    
    try {
        // Generate keys for Bob
        console.log("\n1️⃣ Generating quantum-safe keys for Bob...");
        const bobKeys = kyberService.generateKeypair();
        console.log("   ✅ Bob's keys generated");
        
        // Alice creates shared secret using Bob's public key
        console.log("\n2️⃣ Alice creating shared secret...");
        const { ciphertext, sharedSecret: aliceSecret } = kyberService.encapsulateSecret(bobKeys.publicKey);
        console.log("   ✅ Shared secret created");
        
        // Bob recovers the shared secret
        console.log("\n3️⃣ Bob recovering shared secret...");
        const bobSecret = kyberService.decapsulateSecret(ciphertext, bobKeys.secretKey);
        console.log("   ✅ Secret recovered");
        
        // Verify they match
        console.log("\n4️⃣ Verifying secrets match...");
        if (aliceSecret === bobSecret) {
            console.log("   ✅ SUCCESS! Both have the SAME secret!");
            console.log(`   Secret: ${aliceSecret.substring(0, 32)}...`);
        } else {
            console.log("   ❌ FAILED! Secrets don't match!");
            process.exit(1);
        }
        
        console.log("\n" + "=".repeat(50));
        console.log("🎉 TEST PASSED! Kyber512 is working!");
        console.log("=".repeat(50));
        
    } catch (error) {
        console.error("\n❌ Error:", error);
    }
}

testKyber();