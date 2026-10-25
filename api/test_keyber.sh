# Get keys
KEYS=$(curl -s http://localhost:5000/generate)
PUBKEY=$(echo $KEYS | jq -r '.publicKey')
SECKEY=$(echo $KEYS | jq -r '.secretKey')

# Encapsulate
ENCAP=$(curl -s -X POST http://localhost:5000/encapsulate \
  -H "Content-Type: application/json" \
  -d "{\"publicKey\": \"$PUBKEY\"}")
CIPHER=$(echo $ENCAP | jq -r '.ciphertext')
CLIENT_SECRET=$(echo $ENCAP | jq -r '.sharedSecret')

# Decapsulate
DECAP=$(curl -s -X POST http://localhost:5000/decapsulate \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext\": \"$CIPHER\", \"secretKey\": \"$SECKEY\"}")
SERVER_SECRET=$(echo $DECAP | jq -r '.sharedSecret')

# Compare
echo "Client secret: $CLIENT_SECRET"
echo "Server secret: $SERVER_SECRET"
echo "Match: $([ "$CLIENT_SECRET" = "$SERVER_SECRET" ] && echo "✓ YES" || echo "✗ NO")"





# After running this script, you should see that the client and server secrets match, 
# indicating that the key encapsulation and decapsulation processes are working correctly.
# results in the terminal will show the generated client and server secrets, along with a confirmation of whether they match. 
# If they match, it confirms that the key exchange process is functioning as intended.


# sudo ./test_keyber.sh  
# Client secret: ZKTkniQqsC/z8TEhpw0WXq4jMPt9/tNRDatkvnbd7CY=
# Server secret: ZKTkniQqsC/z8TEhpw0WXq4jMPt9/tNRDatkvnbd7CY=
# Match: ✓ YES
