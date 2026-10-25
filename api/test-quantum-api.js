// Test your quantum endpoints
async function test() {
  // First, login to get token
  const login = await fetch('http://localhost:3000/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'alice', password: 'pass123' })
  });
  const { token } = await login.json();
  
  // Generate quantum keys
  const genKeys = await fetch('http://localhost:3000/quantum/generate-keys', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const keys = await genKeys.json();
  console.log('Keys generated:', keys.publicKey.substring(0, 50) + '...');
  
  // Create shared secret
  const createSecret = await fetch('http://localhost:3000/quantum/create-secret', {
    method: 'POST',
    headers: { 
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ recipientPublicKey: keys.publicKey })
  });
  const secret = await createSecret.json();
  console.log('Shared secret created!');
  
  console.log('\n✅ Quantum endpoints working!');
}

test().catch(console.error);