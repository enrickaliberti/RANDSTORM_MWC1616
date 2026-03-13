const secp256k1 = require('secp256k1');
const crypto = require('crypto');
const bs58 = require('bs58');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const fs = require('fs');
const path = require('path');

// ===================== CONFIGURAZIONE ===================
const CONFIG = {
    HOURS_BEFORE_FIRST_TX: 24,      // 24h per wallet 2014
    STEP_MS: 1,
    WORKERS: Math.min(16, os.cpus().length * 2),
    BATCH_SIZE: 100000,
    PROGRESS_INTERVAL: 5000,
    ENABLE_UNCOMPRESSED: true,
    CHECKPOINT_INTERVAL: 60000,      // Salva stato ogni 60 secondi
    CHECKPOINT_DIR: './checkpoints'   // Directory per i checkpoint
};

// ===================== GESTIONE CHECKPOINT ===================
class CheckpointManager {
    constructor(targetAddr, startTime, endTime) {
        // Crea un ID univoco per questa sessione di attacco
        const safeAddr = targetAddr.replace(/[^a-zA-Z0-9]/g, '_');
        this.checkpointFile = path.join(
            CONFIG.CHECKPOINT_DIR,
            `checkpoint_${safeAddr}_${startTime}_${endTime}.json`
        );
        this.lastSave = 0;

        // Crea directory se non esiste
        if (!fs.existsSync(CONFIG.CHECKPOINT_DIR)) {
            fs.mkdirSync(CONFIG.CHECKPOINT_DIR, { recursive: true });
        }
    }

    // Salva lo stato corrente
    save(workerStats, totalAttempts, startTimestamp) {
        const now = Date.now();
        // Limita la frequenza di salvataggio
        if (now - this.lastSave < CONFIG.CHECKPOINT_INTERVAL / 2) return;

        const checkpoint = {
            timestamp: now,
            totalAttempts,
            elapsedSeconds: (now - startTimestamp) / 1000,
            workers: {},
            version: '1.0'
        };

        // Salva lo stato di ogni worker
        for (const [id, stats] of workerStats) {
            if (stats.lastTs) {
                checkpoint.workers[id] = {
                    lastTs: stats.lastTs,
                    attempts: stats.attempts,
                    rate: stats.rate
                };
            }
        }

        try {
            fs.writeFileSync(this.checkpointFile, JSON.stringify(checkpoint, null, 2));
            this.lastSave = now;
        } catch (err) {
            // Ignora errori di scrittura
        }
    }

    // Carica l'ultimo checkpoint disponibile
    load() {
        try {
            if (fs.existsSync(this.checkpointFile)) {
                const data = fs.readFileSync(this.checkpointFile, 'utf8');
                const checkpoint = JSON.parse(data);

                // Verifica che il checkpoint sia recente (max 24 ore)
                if (Date.now() - checkpoint.timestamp < 24 * 3600000) {
                    return checkpoint;
                } else {
                    console.log('📦 Checkpoint trovato ma troppo vecchio (>24h), riparto da zero');
                }
            }
        } catch (err) {
            console.log('📦 Nessun checkpoint valido trovato, parto da zero');
        }
        return null;
    }

    // Elimina il checkpoint dopo il successo
    clear() {
        try {
            if (fs.existsSync(this.checkpointFile)) {
                fs.unlinkSync(this.checkpointFile);
            }
        } catch (err) {
            // Ignora
        }
    }
}

// ===================== RNG ===================
class V8_MWC1616 {
    constructor(seed) {
        this.state0 = seed >>> 0 || 1;
        this.state1 = seed >>> 0 || 1;
    }

    next() {
        this.state0 = (18030 * (this.state0 & 0xFFFF) + (this.state0 >>> 16)) >>> 0;
        this.state1 = (30903 * (this.state1 & 0xFFFF) + (this.state1 >>> 16)) >>> 0;
        return ((this.state0 << 16) + (this.state1 & 0xFFFF)) >>> 0;
    }

    random() {
        return this.next() / 4294967296;
    }
}

// ===================== RC4 ===================
class RC4_PRNG {
    constructor(seed) {
        this.state = new Uint8Array(256);
        this.i = 0;
        this.j = 0;
        this.init(seed);
    }

    init(seed) {
        for (let i = 0; i < 256; i++) this.state[i] = i;

        let j = 0;
        for (let i = 0; i < 256; i++) {
            j = (j + this.state[i] + seed[i % seed.length]) & 0xFF;
            [this.state[i], this.state[j]] = [this.state[j], this.state[i]];
        }
    }

    nextByte() {
        this.i = (this.i + 1) & 0xFF;
        this.j = (this.j + this.state[this.i]) & 0xFF;
        [this.state[this.i], this.state[this.j]] = [this.state[this.j], this.state[this.i]];
        return this.state[(this.state[this.i] + this.state[this.j]) & 0xFF];
    }

    getBytes(count) {
        const bytes = Buffer.alloc(count);
        for (let i = 0; i < count; i++) {
            bytes[i] = this.nextByte();
        }
        return bytes;
    }
}

// ===================== GENERATORE CHIAVI ===================
function generatePrivateKeyFromTimestamp(ts) {
    const rng = new V8_MWC1616(ts);

    const pool = Buffer.alloc(256);
    for (let i = 0; i < 256; i += 2) {
        const rnd = Math.floor(65536 * rng.random());
        pool[i] = (rnd >>> 8) & 0xFF;
        if (i + 1 < 256) pool[i + 1] = rnd & 0xFF;
    }

    // XOR timestamp DOPO il riempimento
    pool[0] ^= ts & 0xFF;
    pool[1] ^= (ts >> 8) & 0xFF;
    pool[2] ^= (ts >> 16) & 0xFF;
    pool[3] ^= (ts >> 24) & 0xFF;

    const rc4 = new RC4_PRNG(pool);
    return rc4.getBytes(32);
}

// ===================== UTILITÀ BITCOIN ===================
class BitcoinUtils {
    constructor(targetAddr) {
        this.targetAddr = targetAddr;

        try {
            let decoded;
            if (typeof bs58.decode === 'function') {
                decoded = bs58.decode(targetAddr);
            } else if (typeof bs58.default?.decode === 'function') {
                decoded = bs58.default.decode(targetAddr);
            } else {
                throw new Error('bs58.decode non disponibile');
            }

            this.targetHash160 = decoded.slice(1, 21);
            this.targetHex = this.targetHash160.toString('hex');
            this.targetBuffer = Buffer.from(this.targetHash160);

        } catch (err) {
            console.error('❌ Errore decodifica indirizzo:', err.message);
            process.exit(1);
        }
    }

    checkKey(privKey) {
        try {
            // Compressed
            const pubComp = secp256k1.publicKeyCreate(privKey, true);
            const hashComp = this.pubKeyToHash160(pubComp);
            if (hashComp.equals(this.targetBuffer)) {
                return {
                    found: true,
                    compressed: true,
                    hash160: hashComp,
                    address: this.hash160ToAddress(hashComp)
                };
            }

            // Uncompressed
            if (CONFIG.ENABLE_UNCOMPRESSED) {
                const pubUncomp = secp256k1.publicKeyCreate(privKey, false);
                const hashUncomp = this.pubKeyToHash160(pubUncomp);
                if (hashUncomp.equals(this.targetBuffer)) {
                    return {
                        found: true,
                        compressed: false,
                        hash160: hashUncomp,
                        address: this.hash160ToAddress(hashUncomp)
                    };
                }
            }

            return { found: false };
        } catch (err) {
            return { found: false };
        }
    }

    pubKeyToHash160(pubKey) {
        const shaHash = crypto.createHash('sha256').update(pubKey).digest();
        return crypto.createHash('ripemd160').update(shaHash).digest();
    }

    hash160ToAddress(hash160) {
        const versionedPayload = Buffer.concat([Buffer.from([0x00]), hash160]);

        const shaOnce = crypto.createHash('sha256').update(versionedPayload).digest();
        const shaTwice = crypto.createHash('sha256').update(shaOnce).digest();
        const checksum = shaTwice.slice(0, 4);

        const binaryAddress = Buffer.concat([versionedPayload, checksum]);

        if (typeof bs58.encode === 'function') {
            return bs58.encode(binaryAddress);
        } else if (typeof bs58.default?.encode === 'function') {
            return bs58.default.encode(binaryAddress);
        } else {
            return 'ENCODE_ERROR';
        }
    }
}

// ===================== WORKER CON SUPPORTO RIPRESA ===================
if (!isMainThread) {
    const { targetAddr, startMs, endMs, workerId, resumeFromTs } = workerData;
    const utils = new BitcoinUtils(targetAddr);

    let attempts = 0;
    let lastProgressTime = Date.now();
    let lastLogTime = Date.now();

    // Se c'è un timestamp di ripresa, parti da lì
    const startTs = resumeFromTs || startMs;

    for (let ts = startTs; ts <= endMs; ts++) {
        const privKey = generatePrivateKeyFromTimestamp(ts);

        const result = utils.checkKey(privKey);
        if (result.found) {
            parentPort.postMessage({
                found: true,
                timestamp: ts,
                privKey: privKey.toString('hex').toUpperCase(),
                compressed: result.compressed,
                address: result.address,
                attempts: attempts,
                workerId: workerId
            });
            return;
        }

        attempts++;

        const now = Date.now();
        if (now - lastProgressTime > CONFIG.PROGRESS_INTERVAL) {
            const rate = Math.floor(attempts / ((now - lastLogTime) / 1000));
            lastLogTime = now;

            parentPort.postMessage({
                progress: true,
                attempts: attempts,
                currentTs: ts,
                rate: rate,
                workerId: workerId
            });
            lastProgressTime = now;
        }
    }

    parentPort.postMessage({
        done: true,
        attempts: attempts,
        workerId: workerId
    });
}

// =================== MAIN CON CHECKPOINT ===================
class Cracker2011 {
    constructor(targetAddr, firstTxDate) {
        this.targetAddr = targetAddr;
        this.firstTxDate = new Date(firstTxDate);
        this.startTime = this.firstTxDate.getTime() - (CONFIG.HOURS_BEFORE_FIRST_TX * 3600000);
        this.endTime = this.firstTxDate.getTime();

        console.log('🔄 Inizializzazione BitcoinUtils...');
        this.utils = new BitcoinUtils(targetAddr);

        // Inizializza checkpoint manager
        this.checkpointManager = new CheckpointManager(targetAddr, this.startTime, this.endTime);

        this.totalAttempts = 0;
        this.startTimestamp = Date.now();
        this.workers = [];
        this.found = false;
        this.workerStats = new Map();

        // Timer per salvataggio automatico
        this.checkpointTimer = null;
    }

    async crack() {
        this.printBanner();

        // Carica checkpoint se disponibile
        const checkpoint = this.checkpointManager.load();
        const workerResumePoints = new Map();

        if (checkpoint) {
            console.log(`📦 Checkpoint trovato! Ripresa da: ${new Date(checkpoint.timestamp).toLocaleString()}`);
            console.log(`📊 Tentativi già effettuati: ${checkpoint.totalAttempts.toLocaleString()}`);

            // Prepara punti di ripresa per ogni worker
            for (const [id, workerData] of Object.entries(checkpoint.workers)) {
                if (workerData.lastTs) {
                    workerResumePoints.set(parseInt(id), workerData.lastTs);
                }
            }

            this.totalAttempts = checkpoint.totalAttempts;
        }

        const totalTimestamps = this.endTime - this.startTime;
        const timestampsPerWorker = Math.ceil(totalTimestamps / CONFIG.WORKERS);

        console.log(`📊 Totale timestamp: ${totalTimestamps.toLocaleString()}`);
        console.log(`📊 Tentativi totali: ${(totalTimestamps * (CONFIG.ENABLE_UNCOMPRESSED ? 2 : 1)).toLocaleString()}`);
        console.log(`⚡ Velocità stimata: ~${CONFIG.WORKERS * 1000}/s`);
        console.log(`⏱️  Tempo stimato: ${this.estimateTime(totalTimestamps)}`);
        console.log("=".repeat(70));

        const workerPromises = [];

        for (let i = 0; i < CONFIG.WORKERS; i++) {
            const workerStart = this.startTime + (i * timestampsPerWorker);
            const workerEnd = Math.min(
                this.startTime + ((i + 1) * timestampsPerWorker),
                this.endTime
            );

            if (workerStart >= this.endTime) break;

            // Determina se riprendere da un punto specifico
            const resumeFrom = workerResumePoints.get(i);
            const actualStart = resumeFrom ? resumeFrom + 1 : workerStart;

            if (actualStart > workerEnd) {
                console.log(`⏭️  Worker ${i} già completato (salta)`);
                continue;
            }

            console.log(`🚀 Worker ${i}: ${new Date(actualStart).toLocaleTimeString()} → ${new Date(workerEnd).toLocaleTimeString()}`);

            const worker = new Worker(__filename, {
                workerData: {
                    targetAddr: this.targetAddr,
                    startMs: actualStart,
                    endMs: workerEnd,
                    workerId: i,
                    resumeFromTs: resumeFrom
                }
            });

            this.workerStats.set(i, {
                attempts: 0,
                rate: 0,
                lastTs: actualStart,
                start: actualStart,
                end: workerEnd
            });

            workerPromises.push(this.handleWorker(worker, i));
            this.workers.push(worker);
        }

        // Avvia salvataggio automatico ogni minuto
        this.checkpointTimer = setInterval(() => {
            this.checkpointManager.save(this.workerStats, this.totalAttempts, this.startTimestamp);
        }, CONFIG.CHECKPOINT_INTERVAL);

        this.startMonitoring();
        await Promise.race(workerPromises);

        // Pulizia
        if (this.checkpointTimer) {
            clearInterval(this.checkpointTimer);
        }
    }

    handleWorker(worker, id) {
        return new Promise((resolve) => {
            worker.on('message', (msg) => {
                if (msg.found) {
                    this.found = true;
                    this.printSuccess(msg);

                    // Elimina checkpoint (non serve più)
                    this.checkpointManager.clear();

                    // Termina altri worker
                    this.workers.forEach(w => w !== worker && w.terminate());

                    // Ferma salvataggio checkpoint
                    if (this.checkpointTimer) {
                        clearInterval(this.checkpointTimer);
                    }

                    resolve(msg);
                }

                if (msg.progress) {
                    const stats = this.workerStats.get(id);
                    if (stats) {
                        stats.attempts = msg.attempts;
                        stats.rate = msg.rate;
                        stats.lastTs = msg.currentTs;
                    }
                    this.totalAttempts += msg.attempts - (this.workerStats.get(id)?.prevAttempts || 0);
                    if (stats) stats.prevAttempts = msg.attempts;
                }
            });

            worker.on('error', (err) => {
                console.error(`\n❌ Worker ${id} error:`, err);
            });
        });
    }

    startMonitoring() {
        setInterval(() => {
            if (this.found) return;

            let totalRate = 0;
            let activeWorkers = 0;

            for (const stats of this.workerStats.values()) {
                if (stats.rate > 0) {
                    totalRate += stats.rate;
                    activeWorkers++;
                }
            }

            const elapsed = (Date.now() - this.startTimestamp) / 1000;

            // Salva checkpoint periodicamente
            this.checkpointManager.save(this.workerStats, this.totalAttempts, this.startTimestamp);

            process.stdout.write(
                `\r⏳ Tentativi: ${this.totalAttempts.toLocaleString()} | ` +
                `Velocità: ${totalRate.toLocaleString()}/s | ` +
                `Worker attivi: ${activeWorkers} | ` +
                `Tempo: ${elapsed.toFixed(0)}s | ` +
                `💾 Checkpoint salvato`
            );
        }, 1000);
    }

    printBanner() {
        console.log("\n" + "═".repeat(80));
        console.log("🪙 RANDSTORM 2014 - CON CHECKPOINT AUTOMATICO");
        console.log("═".repeat(80));
        console.log(`🎯 Target: ${this.targetAddr}`);
        console.log(`📅 Prima TX: ${this.firstTxDate.toISOString()}`);
        console.log(`🔍 Finestra: ${CONFIG.HOURS_BEFORE_FIRST_TX} ore PRIMA`);
        console.log(`📆 Da: ${new Date(this.startTime).toISOString()}`);
        console.log(`📆 A: ${new Date(this.endTime).toISOString()}`);
        console.log(`🧵 Worker: ${CONFIG.WORKERS}`);
        console.log(`💾 Checkpoint: ogni ${CONFIG.CHECKPOINT_INTERVAL/1000}s in ${CONFIG.CHECKPOINT_DIR}`);
        console.log("═".repeat(80));
    }

    printSuccess(msg) {
        const elapsed = (Date.now() - this.startTimestamp) / 1000;

        console.log("\n\n🔥".repeat(40));
        console.log("🎉 CHIAVE TROVATA! 🎉");
        console.log("🔥".repeat(40));
        console.log(`\n📅 Timestamp: ${msg.timestamp} (${new Date(msg.timestamp).toISOString()})`);
        console.log(`🔑 Private Key: ${msg.privKey}`);
        console.log(`📦 Formato: ${msg.compressed ? 'COMPRESSED' : 'UNCOMPRESSED'}`);
        console.log(`🎯 Indirizzo: ${msg.address}`);
        console.log(`✅ Verifica: ${msg.address === this.targetAddr ? 'OK' : 'ERRORE'}`);
        console.log(`\n⏱️  Tempo: ${elapsed.toFixed(1)}s`);
        console.log(`📊 Tentativi: ${msg.attempts.toLocaleString()}`);
        console.log(`🧹 Checkpoint puliti`);
        console.log("🔥".repeat(40) + "\n");

        // Salva risultato
        const result = {
            address: this.targetAddr,
            privateKey: msg.privKey,
            timestamp: msg.timestamp,
            date: new Date(msg.timestamp).toISOString(),
            compressed: msg.compressed,
            attempts: this.totalAttempts,
            elapsedSeconds: elapsed
        };

        fs.writeFileSync(
            `wallet_cracked_${Date.now()}.json`,
            JSON.stringify(result, null, 2)
        );
        console.log("💾 Risultato salvato su file");
    }

    estimateTime(totalTimestamps) {
        const attemptsPerSecond = CONFIG.WORKERS * 1000;
        const seconds = totalTimestamps / attemptsPerSecond;

        if (seconds < 60) return `${seconds.toFixed(0)}s`;
        if (seconds < 3600) return `${(seconds/60).toFixed(1)}m`;
        return `${(seconds/3600).toFixed(1)}h`;
    }
}

// ===================== MAIN ===================
async function main() {
    console.log('🔍 Verifica versione bs58...');
    console.log('bs58 type:', typeof bs58);
    console.log('bs58.decode available:', typeof bs58.decode);

    const targetAddress = "1NUhcfvRthmvrHf1PAJKe5uEzBGK44ASBD";
    const firstTxDate = "2014-03-01T12:00:00Z";

    const cracker = new Cracker2011(targetAddress, firstTxDate);
    await cracker.crack();
}

if (isMainThread) {
    process.on('SIGINT', () => {
        console.log('\n\n🛑 Ricevuto CTRL+C, salvo checkpoint prima di uscire...');
        // Il checkpoint viene salvato automaticamente dal timer,
        // ma forziamo un ultimo salvataggio
        setTimeout(() => process.exit(0), 1000);
    });

    main().catch(console.error);
}

module.exports = { Cracker2011, generatePrivateKeyFromTimestamp };
