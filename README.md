# TAP Token Auth Signatures

```javascript
import * as secp from '@noble/secp256k1';
import secp256k1 from 'secp256k1';
import {createHash} from "node:crypto";

// creating a key pair
const pair = await createKeyPair();

// creating a signed auth op
//
// auth ops must be inscribed and tapped by the authority that wants to connect
// the specified tickers. after tapping, the specified tickers are associated with the account that tapped it.
//
// each hash must be unique. therefore the authority must provide a salt to make sure the resulting hash is unique.

const authResult = await createAuth(
    pair.pk,
    pair.pub,
    'auth',
    ['gib'],
    Math.random()
)

// creates a signed redeem op.
//
// redeem ops should be issued by the authority that inscribed the corresponding auth op like above.
// anyone receiving a redeem op can inscribe it but it can only be used once and will be only credited
// to the signed recipients as of "items".
//
// each hash must be unique. therefore the authority must provide a salt to make sure the resulting hash is unique.
const redeemResult = await createAuth(
    pair.pk,
    pair.pub,
    'redeem',
    {
        items : [
            {
                "tick": "gib",
                "amt": "546",
                "address" : "bc1p9lpne8pnzq87dpygtqdd9vd3w28fknwwgv362xff9zv4ewxg6was504w20"
            }
        ],
        auth : 'fd3664a56cf6d14b21504e5d83a3d4867ee256f06cbe3bddf2787d6a80a86078i0',
        data : ''
    },
    Math.random()
)

console.log('####### RANDOM PAIR ########');
console.log(pair);

console.log('####### AUTH RESULT ########');
console.log(authResult);

console.log('####### REDEEM RESULT ########');
console.log(redeemResult);

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
 * Creates an auth inscription op in its result
 *
 * @param privKey
 * @param pubKey
 * @param messageKey
 * @param message
 * @param salt
 * @returns {Promise<{result: string, test: {valid: boolean, pubRecovered: string, pub: string}}>}
 */
async function createAuth(privKey, pubKey, messageKey, message, salt) {

    privKey = Buffer.from(privKey, 'hex');
    pubKey = Buffer.from(pubKey, 'hex');

    let proto = {
        p : 'tap',
        op : 'token-auth',
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
 * Creates a buffered hash from given content.
 *
 * @param content
 * @returns {Buffer}
 */
function sha256(content) {
    return createHash('sha256').update(content).digest();
}
```
