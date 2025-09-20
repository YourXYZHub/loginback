const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Connection, PublicKey, clusterApiUrl } = require('@solana/web3.js');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const { createClient } = require('@supabase/supabase-js');

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE;
const supabase = createClient(supabaseUrl, supabaseKey);

// Solana connection
const connection = new Connection(clusterApiUrl('mainnet-beta'));

// Generate a nonce for signing
app.get('/api/nonce', (req, res) => {
  const nonce = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  const message = `Please sign this message to authenticate with our app. Nonce: ${nonce}, Timestamp: ${Date.now()}`;
  
  res.json({ message, nonce });
});

// Verify signature and check user in Supabase
app.post('/api/verify', async (req, res) => {
  const { publicKey, signature, message } = req.body;

  try {
    // Verify the signature
    const publicKeyBytes = new PublicKey(publicKey).toBytes();
    const signatureBytes = bs58.decode(signature);
    const messageBytes = new TextEncoder().encode(message);

    const isValid = nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      publicKeyBytes
    );

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // Check if user exists in Supabase
    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, handle, image_url, created_at')
      .eq('wallet', publicKey)
      .single();

    if (error) {
      if (error.code === 'PGRST116') { // No rows returned
        return res.json({ registered: false });
      }
      throw error;
    }

    res.json({
      registered: true,
      profile: user
    });

  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
