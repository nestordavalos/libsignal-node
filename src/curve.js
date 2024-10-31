
import { generateKeyPair, sharedKey, sign, verify } from '../build/curve25519.js';
import { generateKeyPairSync, randomBytes, diffieHellman, createPrivateKey, createPublicKey } from 'crypto';
// from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js
const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);
  
const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    } else {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}

export function generateKeyPair() {
    if(typeof generateKeyPairSync === 'function') {
        const {publicKey: publicDerBytes, privateKey: privateDerBytes} = generateKeyPairSync(
            'x25519',
            {
                publicKeyEncoding: { format: 'der', type: 'spki' },
                privateKeyEncoding: { format: 'der', type: 'pkcs8' }
            }
        );
        // 33 bytes
        // first byte = 5 (version byte)
        const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length-1, PUBLIC_KEY_DER_PREFIX.length + 32);
        pubKey[0] = 5;
    
        const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);
    
        return {
            pubKey,
            privKey
        };
    } else {
        const keyPair = generateKeyPair(randomBytes(32));
        return {
            privKey: Buffer.from(keyPair.private),
            pubKey: Buffer.from(keyPair.public),
        };
    }
}

export function calculateAgreement(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }

    if(typeof diffieHellman === 'function') {
        const nodePrivateKey = createPrivateKey({
            key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = createPublicKey({
            key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
            format: 'der',
            type: 'spki'
        });
        
        return diffieHellman({
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey,
        });
    } else {
        const secret = sharedKey(privKey, pubKey);
        return Buffer.from(secret);
    }
}

export function calculateSignature(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return Buffer.from(sign(privKey, message));
}

export function verifySignature(pubKey, msg, sig) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    return verify(pubKey, msg, sig);
}
