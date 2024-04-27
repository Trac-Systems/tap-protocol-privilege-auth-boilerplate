import * as secp from '@noble/secp256k1';
import secp256k1 from 'secp256k1';
import {createHash} from "node:crypto";

// IMPORTANT: requires Node 20+

// creating a random key pair
// you really may want to run this once, store your private and public keys being generated and use the below with these.
const pair = await createKeyPair();

// creating an authority as of token-auth described here https://github.com/BennyTheDev/tap-protocol-specs.
//
// auth ops must be inscribed and tapped (inscribe + sent to yourself) by the authority that wants to allow
// the use of specified tickers being handled by the authority (or empty message array for any token that the authority controls).
// after tapping, the specified tickers are associated with the account that tapped it.
//
// each hash must be unique. therefore the authority must provide a salt to make sure the resulting hash is unique.
// if your authority needs the capability to re-index and filter already signed auth creation ops,
// then the salt should be something unique like an inscription id that it refers to.
const authResult = await signAuth(
    pair.pk,
    pair.pub,
    'auth',
    {
        'name' : 'Some privilege authority'
    },
    Math.random()
)

// generate a signed mint inscription text, ready for broadcasting
const mintResult = await signMint(
    pair.pk,
    pair.pub,
    'randomtoken4',
    1000,
    'tb1pf9jluy2g797290uq5nutqm2yuynds6uf868ytc37nht53c5j8w3s7nfta7',
    Math.random()
)

// generate a signed DMT mint inscription text, ready for broadcasting
const dmtMintResult = await signDmtMint(
    pair.pk,
    pair.pub,
    'nat',
    190002,
    '825e287bb7dd163ed633110e31bc6abb6c80815ca68b7dd3cc71d729ecaaa3dci0',
    'tb1pf9jluy2g797290uq5nutqm2yuynds6uf868ytc37nht53c5j8w3s7nfta7',
    Math.random()
)

const signVerificationResult = await signVerification(
    pair.pk,
    pair.pub,
    'e349a9126a9476eb534457a7e78c748aeca67ec4d53fa9f0772408fb7233a9fei0',
    'cea505f61f375ea2d8ea56f593e6b436f963753616c2095e755cb5ca4a6df85c',
    'super collection',
    111,
    'tb1pltn4mqlpxxswxhmkj2ejdd0z98v74nr0xxdresvwvp5cyvctm0zs3m750l',
    Math.random()
)


// creating a random pair for demonstration.
// in a production environment, the authority stores its private key at a safe place and signs
// the messages on demand.
console.log('####### RANDOM PAIR ########');
console.log(pair);

console.log('####### CREATE PRIVILEGE AUTH RESULT ########');
console.log(authResult);

console.log('####### CREATE MINT RESULT ########');
console.log(mintResult);

console.log('####### CREATE DMT MINT RESULT ########');
console.log(dmtMintResult);

console.log('####### CREATE VERIFICATION RESULT ########');
console.log(signVerificationResult);

/**
 * Generates a random keypair
 *
 * @returns {Promise<{pk: string, pub: string}>}
 */
async function createKeyPair() {
    let privKey;

    do {
        privKey = secp.utils.randomPrivateKey();
    } while (!secp256k1.privateKeyVerify(privKey))

    const pubKey = secp.getPublicKey(privKey);

    return {
        pk: Buffer.from(privKey).toString('hex'),
        pub: Buffer.from(pubKey).toString('hex')
    };
}

/**
 * Creates an auth inscription op as signed inscription text
 *
 * @param privKey
 * @param pubKey
 * @param messageKey
 * @param message
 * @param salt
 * @returns {Promise<{result: string, test: {valid: boolean, pubRecovered: string, pub: string}}>}
 */
async function signAuth(privKey, pubKey, messageKey, message, salt) {

    privKey = Buffer.from(privKey, 'hex');
    pubKey = Buffer.from(pubKey, 'hex');

    let proto = {
        p : 'tap',
        op : 'privilege-auth',
        sig: null,
        hash : null,
        salt : ''+salt
    }

    const msgHash = sha256(JSON.stringify(message) + proto.salt);
    const signature = await secp.signAsync(msgHash, privKey);

    proto[messageKey] = message;
    proto.sig = { v : '' + signature.recovery, r : signature.r.toString(), s : signature.s.toString()};
    proto.hash = Buffer.from(msgHash).toString('hex');

    const test_proto = JSON.parse(JSON.stringify(proto));
    const test_msgHash = sha256(JSON.stringify(test_proto[messageKey]) + test_proto.salt);
    const isValid = secp.verify(signature, test_msgHash, pubKey);
    let test = new secp.Signature(BigInt(proto.sig.r), BigInt(proto.sig.s), parseInt(proto.sig.v));

    return {
        test : {
            valid : isValid,
            pub : Buffer.from(pubKey).toString('hex'),
            pubRecovered : test.recoverPublicKey(msgHash).toHex()
        },
        result : JSON.stringify(proto)
    }
}

/**
 * Creates and signs a mint inscription text for regular tap mints.
 * Please note that instead of a random value, you might want to pass an incrementing number like a nonce.
 * This is important if you intend to re-index your authority's indexer. This also means the authority has to store which message hash has been sent already and with which nonce.
 * TAP indexers will ignoe existing message hashes as they are only valid once.
 *
 * @param privKey
 * @param pubKey
 * @param ticker
 * @param amount
 * @param salt
 * @returns {Promise<{result: string, test: {valid: boolean, pubRecovered: string, pub: *}}>}
 */
async function signMint(privKey, pubKey, ticker, amount, address, salt) {

    privKey = Buffer.from(privKey, 'hex');
    pubKey = Buffer.from(pubKey, 'hex');

    let proto = {
        p : 'tap',
        op : 'token-mint',
        tick : ticker,
        amt : amount,
        prv: {
            sig : null,
            hash : null,
            address : address,
            salt : ''+salt
        }
    }

    const msgHash = sha256(proto.p + '-' + proto.op + '-' + proto.tick + '-' + proto.amt + '-' + proto.prv.address + '-' + proto.prv.salt);
    const signature = await secp.signAsync(msgHash, privKey);

    proto.prv.sig = { v : '' + signature.recovery, r : signature.r.toString(), s : signature.s.toString()};
    proto.prv.hash = Buffer.from(msgHash).toString('hex');

    const test_proto = JSON.parse(JSON.stringify(proto));
    const test_msgHash = sha256(test_proto.p + '-' + test_proto.op + '-' + test_proto.tick + '-' + test_proto.amt + '-' + test_proto.prv.address + '-' + test_proto.prv.salt);
    const isValid = secp.verify(signature, test_msgHash, pubKey);
    let test = new secp.Signature(BigInt(proto.prv.sig.r), BigInt(proto.prv.sig.s), parseInt(proto.prv.sig.v));

    return {
        test : {
            valid : isValid,
            pub : Buffer.from(pubKey).toString('hex'),
            pubRecovered : test.recoverPublicKey(msgHash).toHex()
        },
        result : JSON.stringify(proto)
    }
}

/**
 * Creates and signs a mint inscription text for regular tap DMT mints.
 * Please note that instead of a random value, you might want to pass an incrementing number like a nonce.
 * This is important if you intend to re-index your authority's indexer. This also means the authority has to store which message hash has been sent already and with which nonce.
 * TAP indexers will ignoe existing message hashes as they are only valid once.
 *
 * TODO: once dep (dependency) is optional for DMT, we need to sign without it and recreate the messageHash accordingly
 *
 * @param privKey
 * @param pubKey
 * @param ticker
 * @param block
 * @param dependency
 * @param salt
 * @returns {Promise<{result: string, test: {valid: boolean, pubRecovered: string, pub: *}}>}
 */
async function signDmtMint(privKey, pubKey, ticker, block, dependency, address, salt) {

    privKey = Buffer.from(privKey, 'hex');
    pubKey = Buffer.from(pubKey, 'hex');

    let proto = {
        p : 'tap',
        op : 'dmt-mint',
        tick : ticker.toLowerCase(),
        blk : block,
        dep : dependency,
        prv: {
            sig : null,
            hash : null,
            address : address,
            salt : ''+salt
        }
    }

    const msgHash = sha256(proto.p + '-' + proto.op + '-' + proto.tick + '-' + proto.blk + '-' + proto.dep + '-' + proto.prv.address + '-' + proto.prv.salt);
    const signature = await secp.signAsync(msgHash, privKey);

    proto.prv.sig = { v : '' + signature.recovery, r : signature.r.toString(), s : signature.s.toString()};
    proto.prv.hash = Buffer.from(msgHash).toString('hex');

    const test_proto = JSON.parse(JSON.stringify(proto));
    const test_msgHash = sha256(test_proto.p + '-' + test_proto.op + '-' + test_proto.tick + '-' + test_proto.blk + '-' + test_proto.dep + '-' + test_proto.prv.address + '-' + test_proto.prv.salt);
    const isValid = secp.verify(signature, test_msgHash, pubKey);
    let test = new secp.Signature(BigInt(proto.prv.sig.r), BigInt(proto.prv.sig.s), parseInt(proto.prv.sig.v));

    return {
        test : {
            valid : isValid,
            pub : Buffer.from(pubKey).toString('hex'),
            pubRecovered : test.recoverPublicKey(msgHash).toHex()
        },
        result : JSON.stringify(proto)
    }
}

/**
 * Create signed inscription texts for general-purpose file hashes (sha256).
 * These types of inscriptions enable authorities to verify file hashes of any file type like images, videos, etc.
 * The inscriptions can be traded or being used to track valid assets (for example valid ordinals).
 *
 * By inscribing a signed verification, the address given owns the provenance and can use the tap protocol to prove that an authority granted its privilege.
 * An authority should either be the issuer of the files or acts in the issuer's behalf.
 * Therefore, an issuer should point to the ordinals id of the authority through offchain methods (socials, project website, chats, etc).
 *
 * Since this is a collection driven approach, a collection name and a sequence have to be passed.
 * The collection name may consist of up to 512 symbols (as of unicode).

 * The sequence must be an unsigned integer and may be arbitrary but not larger than 9007199254740991.
 * It is recommended to use the sequence number for collectible IDs. If every hash being issued is unique, simply set it to 0.

 * If your hashes are NOT unique, you have to assign different sequence numbers,
 * otherwise the tap protocol considers duplicates as processed.
 *
 * If you verify the content of existing ordinals, you may consider to use their ordinals ids (not the ordinals number) as salt.
 *
 * @param privKey
 * @param pubKey
 * @param privilege_authority_id
 * @param sha256_hash
 * @param collection
 * @param sequence
 * @param address
 * @param salt
 * @returns {Promise<{result: string, test: {valid: boolean, pubRecovered: string, pub: *}}>}
 */
async function signVerification(privKey, pubKey, privilege_authority_id, sha256_hash, collection, sequence, address, salt) {

    privKey = Buffer.from(privKey, 'hex');
    pubKey = Buffer.from(pubKey, 'hex');

    let proto = {
        p : 'tap',
        op : 'privilege-auth',
        sig : null,
        hash : null,
        address : address,
        salt : ''+salt,
        prv : privilege_authority_id,
        verify : sha256_hash,
        col : collection,
        seq : sequence
    }

    const msgHash = sha256(proto.prv + '-' + proto.col + '-' + proto.verify + '-'  + proto.seq + '-' + proto.address + '-' + proto.salt);
    const signature = await secp.signAsync(msgHash, privKey);

    proto.sig = { v : '' + signature.recovery, r : signature.r.toString(), s : signature.s.toString()};
    proto.hash = Buffer.from(msgHash).toString('hex');

    const test_proto = JSON.parse(JSON.stringify(proto));
    const test_msgHash = sha256(test_proto.prv + '-' + test_proto.col + '-' + test_proto.verify + '-'  + test_proto.seq + '-' + test_proto.address + '-' + test_proto.salt);
    const isValid = secp.verify(signature, test_msgHash, pubKey);
    let test = new secp.Signature(BigInt(proto.sig.r), BigInt(proto.sig.s), parseInt(proto.sig.v));

    return {
        test : {
            valid : isValid,
            pub : Buffer.from(pubKey).toString('hex'),
            pubRecovered : test.recoverPublicKey(msgHash).toHex()
        },
        result : JSON.stringify(proto)
    }
}


/**
 * Creates a buffered hash from given content.
 *
 * @param content
 * @returns {Buffer}
 */
function sha256(content) {
    return createHash('sha256').update(content).digest();
}