import * as asn1 from 'asn1.js';
import { GetPublicKeyCommand, KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { computeAddress, JsonRpcProvider, parseUnits, SigningKey, Transaction, keccak256 } from 'ethers';

const kms = new KMSClient({
    credentials: {
        accessKeyId: '<access_key_id>',
        secretAccessKey: '<access_secret>',
    },
    region: '<region>',
});

const keyId = '<KMS key id>';

const EcdsaSigAsnParse = asn1.define('EcdsaSig', function(this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
    this.seq().obj(
        this.key('r').int(),
        this.key('s').int(),
    );
});

const EcdsaPubKey = asn1.define('EcdsaPubKey', function(this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(
        this.key('algo').seq().obj(
            this.key('a').objid(),
            this.key('b').objid(),
        ),
        this.key('pubKey').bitstr()
    );
});

async function sign(msgHash, keyId) {
    // For more information, see https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/kms/command/SignCommand
    const signCommand = new SignCommand({
        KeyId: keyId,
        Message: hexStringToUint8Array(msgHash),
        MessageType: 'DIGEST',
        SigningAlgorithm: 'ECDSA_SHA_256',
    });
    return await kms.send(signCommand);
}

async function getPublicKey(keyPairId: string) {
    const command = new GetPublicKeyCommand({
        KeyId: keyPairId,
    });
    return await kms.send(command);
}

function getEthereumAddress(publicKey: Uint8Array): string {
    if(publicKey === undefined) {
        throw new Error('Public key is undefined.');
    }
    // The public key is ASN1 encoded in a format according to
    // https://tools.ietf.org/html/rfc5480#section-2
    // I used https://lapo.it/asn1js to figure out how to parse this
    // and defined the schema in the EcdsaPubKey object
    let res = EcdsaPubKey.decode(Buffer.from(publicKey), 'der')
    let pubKeyBuffer : Buffer = res.pubKey.data;

    // The public key starts with a 0x04 prefix that needs to be removed
    // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    // But you can just convert to hex string because ethers.js will do the conversion for you.
    const EthAddr = computeAddress('0x' +pubKeyBuffer.toString('hex'));
    console.log("Generated Ethreum address: " + EthAddr);
    return EthAddr;
}

async function findEthereumSig(msgHash) {
    let signature = await sign(msgHash, keyId);
    if (signature.Signature == undefined) {
        throw new Error('Signature is undefined.');
    }

    let decoded = EcdsaSigAsnParse.decode(Buffer.from(signature.Signature), 'der');
    let r: bigint = decoded.r;
    let s: bigint = decoded.s;

    // convert to decimal
    console.log("r: " + r);
    console.log("s: " + s);

    let tempsig = decoded.r.toString(16) + decoded.s.toString(16);
    console.log(tempsig);

    const secp256k1N: bigint = BigInt(
        '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
    );
    const secp256k1halfN = secp256k1N / BigInt(2);

    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    if (s > secp256k1halfN) {
        console.log("s is on the wrong side of the curve... flipping - tempsig: " + tempsig + " length: " + tempsig.length);
        // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
        // if s < half the curve we need to invert it
        // s = curve.n - s
        s = secp256k1N - BigInt(s);
    }
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    return { r, s }
}

function findRightKey(msg: string, r, s, expectedEthAddr: string) {
    // This is the wrapper function to find the right v value
    // There are two matching signatues on the elliptic curve
    // we need to find the one that matches to our public key
    // it can be v = 27 or v = 28
    let vf = 27;
    let pubKey = SigningKey.recoverPublicKey(
        msg,
        {
            r: '0x' + r.toString(16),
            s: '0x' + s.toString(16),
            v: vf,
        }
    );

    pubKey = computeAddress(pubKey);
    if (pubKey != expectedEthAddr) {
        // if the pub key for v = 27 does not match
        // it has to be v = 28
        vf = 28;
        pubKey = SigningKey.recoverPublicKey(
            msg,
            {
                r: '0x' + r.toString(16),
                s: '0x' + s.toString(16),
                v: vf,
            }
        );
        pubKey = computeAddress(pubKey);
    }
    console.log("Found the right ETH Address: " + pubKey + " v: " + vf);
    return { pubKey, vf };
}

function hexStringToUint8Array(hex: string): Uint8Array {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    if (hex.length % 2 !== 0) throw new Error('Invalid hex string');

    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}

txTest();
async function txTest() {
    console.log('test');
    // Use a provider using ethers.js instead of web3.js
    const provider = new JsonRpcProvider('https://eth-sepolia.g.alchemy.com/v2/<alchemy_key>');

    let pubKey = await getPublicKey(keyId);
    let ethAddr = getEthereumAddress(pubKey.PublicKey ?? new Uint8Array());;

    const receiverAddr = '<receiver_address>';
    const etherValue = parseUnits('1000000', 'gwei'); // 1,000,000 gwei = 0.001 ether
    const chainId = (await provider.getNetwork()).chainId;
    const nonce = await provider.getTransactionCount(ethAddr);
    let gasLimit = await provider.estimateGas({
        from: ethAddr,
        to: receiverAddr,
        nonce: nonce,
        value: etherValue,
        chainId: chainId,
    });
    const feeData = await provider.getFeeData();
    // For more informations, https://docs.ethers.org/v6/api/providers/#FeeData
    const maxFeePerGas = feeData.maxFeePerGas ? (feeData.maxFeePerGas * BigInt(3)) / BigInt(2) : parseUnits("50", "gwei");
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas ? feeData.maxPriorityFeePerGas : parseUnits("2", "gwei");

    // Type 2 (EIP-1559) transaction params
    const tx = new Transaction();
    tx.to = receiverAddr;
    tx.nonce = nonce;
    tx.value = etherValue;
    tx.chainId = chainId;
    tx.maxFeePerGas = maxFeePerGas;
    tx.maxPriorityFeePerGas = maxPriorityFeePerGas;
    tx.gasLimit = gasLimit;

    console.log(tx.toJSON());

    const txHash = keccak256(tx.unsignedSerialized);
    const sig = await findEthereumSig(txHash);
    const recoveredPubAddr = findRightKey(txHash, sig.r, sig.s, ethAddr);

    // Adjust the v value considering EIP-155
    // For more infomation, see {https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md}
    const chainIdV = chainId * BigInt(2) + BigInt(35);
    const v = recoveredPubAddr.vf === 27 ? chainIdV : chainIdV + BigInt(1);

    tx.signature = {
        r: '0x' + sig.r.toString(16),
        s: '0x' + sig.s.toString(16),
        v: v,
    };
    console.log(tx.from);
    if(tx.from === recoveredPubAddr.pubKey) {
        console.log('Transaction from address matches the recovered address');
    }

    // Send signed tx to ethereum network
    const txResponse = await provider.broadcastTransaction(tx.serialized);
    const txReceipt = await txResponse.wait();
    console.log("signAndSendTx txReceipt. Tx Hash: " + txReceipt?.hash);

    return {
        success: true,
    }
}
