/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { secp256k1 as _secp, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hex, base58, base58check as _b58, bech32, bech32m } from '@scure/base';
import * as P from 'micro-packed';
const { ProjectivePoint: ProjPoint, sign: _signECDSA, getPublicKey: _pubECDSA } = _secp;
const CURVE_ORDER = _secp.CURVE.n;
// Same as value || def, but doesn't overwrites zero ('0', 0, 0n, etc)
const def = (value, def) => (value === undefined ? def : value);
const isBytes = P.isBytes;
const hash160 = (msg) => ripemd160(sha256(msg));
const sha256x2 = (...msgs) => sha256(sha256(concat(...msgs)));
const concat = P.concatBytes;
// Make base58check work
export const base58check = _b58(sha256);
export function cloneDeep(obj) {
    if (Array.isArray(obj))
        return obj.map((i) => cloneDeep(i));
    // slice of nodejs Buffer doesn't copy
    else if (obj instanceof Uint8Array)
        return Uint8Array.from(obj);
    // immutable
    else if (['number', 'bigint', 'boolean', 'string', 'undefined'].includes(typeof obj))
        return obj;
    // null is object
    else if (obj === null)
        return obj;
    // should be last, so it won't catch other types
    else if (typeof obj === 'object') {
        return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, cloneDeep(v)]));
    }
    throw new Error(`cloneDeep: unknown type=${obj} (${typeof obj})`);
}
var PubT;
(function (PubT) {
    PubT[PubT["ecdsa"] = 0] = "ecdsa";
    PubT[PubT["schnorr"] = 1] = "schnorr";
})(PubT || (PubT = {}));
function validatePubkey(pub, type) {
    const len = pub.length;
    if (type === PubT.ecdsa) {
        if (len === 32)
            throw new Error('Expected non-Schnorr key');
        ProjPoint.fromHex(pub); // does assertValidity
        return pub;
    }
    else if (type === PubT.schnorr) {
        if (len !== 32)
            throw new Error('Expected 32-byte Schnorr key');
        schnorr.utils.lift_x(schnorr.utils.bytesToNumberBE(pub));
        return pub;
    }
    else {
        throw new Error('Unknown key type');
    }
}
function isValidPubkey(pub, type) {
    try {
        validatePubkey(pub, type);
        return true;
    }
    catch (e) {
        return false;
    }
}
// low-r signature grinding. Used to reduce tx size by 1 byte.
// noble/secp256k1 does not support the feature: it is not used outside of BTC.
// We implement it manually, because in BTC it's common.
// Not best way, but closest to bitcoin implementation (easier to check)
const hasLowR = (sig) => sig.r < CURVE_ORDER / 2n;
function signECDSA(hash, privateKey, lowR = false) {
    let sig = _signECDSA(hash, privateKey);
    if (lowR && !hasLowR(sig)) {
        const extraEntropy = new Uint8Array(32);
        for (let cnt = 0; cnt < Number.MAX_SAFE_INTEGER; cnt++) {
            extraEntropy.set(P.U32LE.encode(cnt));
            sig = _signECDSA(hash, privateKey, { extraEntropy });
            if (hasLowR(sig))
                break;
        }
    }
    return sig.toDERRawBytes();
}
function tapTweak(a, b) {
    const u = schnorr.utils;
    const t = u.taggedHash('TapTweak', a, b);
    const tn = u.bytesToNumberBE(t);
    if (tn >= CURVE_ORDER)
        throw new Error('tweak higher than curve order');
    return tn;
}
export function taprootTweakPrivKey(privKey, merkleRoot = new Uint8Array()) {
    const u = schnorr.utils;
    const seckey0 = u.bytesToNumberBE(privKey); // seckey0 = int_from_bytes(seckey0)
    const P = ProjPoint.fromPrivateKey(seckey0); // P = point_mul(G, seckey0)
    // seckey = seckey0 if has_even_y(P) else SECP256K1_ORDER - seckey0
    const seckey = P.hasEvenY() ? seckey0 : u.mod(-seckey0, CURVE_ORDER);
    const xP = u.pointToBytes(P);
    // t = int_from_bytes(tagged_hash("TapTweak", bytes_from_int(x(P)) + h)); >= SECP256K1_ORDER check
    const t = tapTweak(xP, merkleRoot);
    // bytes_from_int((seckey + t) % SECP256K1_ORDER)
    return u.numberToBytesBE(u.mod(seckey + t, CURVE_ORDER), 32);
}
export function taprootTweakPubkey(pubKey, h) {
    const u = schnorr.utils;
    const t = tapTweak(pubKey, h); // t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
    const P = u.lift_x(u.bytesToNumberBE(pubKey)); // P = lift_x(int_from_bytes(pubkey))
    const Q = P.add(ProjPoint.fromPrivateKey(t)); // Q = point_add(P, point_mul(G, t))
    const parity = Q.hasEvenY() ? 0 : 1; // 0 if has_even_y(Q) else 1
    return [u.pointToBytes(Q), parity]; // bytes_from_int(x(Q))
}
// Can be 33 or 64 bytes
const PubKeyECDSA = P.validate(P.bytes(null), (pub) => validatePubkey(pub, PubT.ecdsa));
const PubKeySchnorr = P.validate(P.bytes(32), (pub) => validatePubkey(pub, PubT.schnorr));
const SignatureSchnorr = P.validate(P.bytes(null), (sig) => {
    if (sig.length !== 64 && sig.length !== 65)
        throw new Error('Schnorr signature should be 64 or 65 bytes long');
    return sig;
});
function uniqPubkey(pubkeys) {
    const map = {};
    for (const pub of pubkeys) {
        const key = hex.encode(pub);
        if (map[key])
            throw new Error(`Multisig: non-uniq pubkey: ${pubkeys.map(hex.encode)}`);
        map[key] = true;
    }
}
export const NETWORK = {
    bech32: 'bc',
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
};
export const TEST_NETWORK = {
    bech32: 'tb',
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
};
export const PRECISION = 8;
export const DEFAULT_VERSION = 2;
export const DEFAULT_LOCKTIME = 0;
export const DEFAULT_SEQUENCE = 4294967295;
const EMPTY32 = new Uint8Array(32);
// Utils
export const Decimal = P.coders.decimal(PRECISION);
// Exported for tests, internal method
export function _cmpBytes(a, b) {
    if (!isBytes(a) || !isBytes(b))
        throw new Error(`cmp: wrong type a=${typeof a} b=${typeof b}`);
    // -1 -> a<b, 0 -> a==b, 1 -> a>b
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++)
        if (a[i] != b[i])
            return Math.sign(a[i] - b[i]);
    return Math.sign(a.length - b.length);
}
// Coders
// prettier-ignore
export var OP;
(function (OP) {
    OP[OP["OP_0"] = 0] = "OP_0";
    OP[OP["PUSHDATA1"] = 76] = "PUSHDATA1";
    OP[OP["PUSHDATA2"] = 77] = "PUSHDATA2";
    OP[OP["PUSHDATA4"] = 78] = "PUSHDATA4";
    OP[OP["1NEGATE"] = 79] = "1NEGATE";
    OP[OP["RESERVED"] = 80] = "RESERVED";
    OP[OP["OP_1"] = 81] = "OP_1";
    OP[OP["OP_2"] = 82] = "OP_2";
    OP[OP["OP_3"] = 83] = "OP_3";
    OP[OP["OP_4"] = 84] = "OP_4";
    OP[OP["OP_5"] = 85] = "OP_5";
    OP[OP["OP_6"] = 86] = "OP_6";
    OP[OP["OP_7"] = 87] = "OP_7";
    OP[OP["OP_8"] = 88] = "OP_8";
    OP[OP["OP_9"] = 89] = "OP_9";
    OP[OP["OP_10"] = 90] = "OP_10";
    OP[OP["OP_11"] = 91] = "OP_11";
    OP[OP["OP_12"] = 92] = "OP_12";
    OP[OP["OP_13"] = 93] = "OP_13";
    OP[OP["OP_14"] = 94] = "OP_14";
    OP[OP["OP_15"] = 95] = "OP_15";
    OP[OP["OP_16"] = 96] = "OP_16";
    // Control
    OP[OP["NOP"] = 97] = "NOP";
    OP[OP["VER"] = 98] = "VER";
    OP[OP["IF"] = 99] = "IF";
    OP[OP["NOTIF"] = 100] = "NOTIF";
    OP[OP["VERIF"] = 101] = "VERIF";
    OP[OP["VERNOTIF"] = 102] = "VERNOTIF";
    OP[OP["ELSE"] = 103] = "ELSE";
    OP[OP["ENDIF"] = 104] = "ENDIF";
    OP[OP["VERIFY"] = 105] = "VERIFY";
    OP[OP["RETURN"] = 106] = "RETURN";
    // Stack
    OP[OP["TOALTSTACK"] = 107] = "TOALTSTACK";
    OP[OP["FROMALTSTACK"] = 108] = "FROMALTSTACK";
    OP[OP["2DROP"] = 109] = "2DROP";
    OP[OP["2DUP"] = 110] = "2DUP";
    OP[OP["3DUP"] = 111] = "3DUP";
    OP[OP["2OVER"] = 112] = "2OVER";
    OP[OP["2ROT"] = 113] = "2ROT";
    OP[OP["2SWAP"] = 114] = "2SWAP";
    OP[OP["IFDUP"] = 115] = "IFDUP";
    OP[OP["DEPTH"] = 116] = "DEPTH";
    OP[OP["DROP"] = 117] = "DROP";
    OP[OP["DUP"] = 118] = "DUP";
    OP[OP["NIP"] = 119] = "NIP";
    OP[OP["OVER"] = 120] = "OVER";
    OP[OP["PICK"] = 121] = "PICK";
    OP[OP["ROLL"] = 122] = "ROLL";
    OP[OP["ROT"] = 123] = "ROT";
    OP[OP["SWAP"] = 124] = "SWAP";
    OP[OP["TUCK"] = 125] = "TUCK";
    // Splice
    OP[OP["CAT"] = 126] = "CAT";
    OP[OP["SUBSTR"] = 127] = "SUBSTR";
    OP[OP["LEFT"] = 128] = "LEFT";
    OP[OP["RIGHT"] = 129] = "RIGHT";
    OP[OP["SIZE"] = 130] = "SIZE";
    // Boolean logic
    OP[OP["INVERT"] = 131] = "INVERT";
    OP[OP["AND"] = 132] = "AND";
    OP[OP["OR"] = 133] = "OR";
    OP[OP["XOR"] = 134] = "XOR";
    OP[OP["EQUAL"] = 135] = "EQUAL";
    OP[OP["EQUALVERIFY"] = 136] = "EQUALVERIFY";
    OP[OP["RESERVED1"] = 137] = "RESERVED1";
    OP[OP["RESERVED2"] = 138] = "RESERVED2";
    // Numbers
    OP[OP["1ADD"] = 139] = "1ADD";
    OP[OP["1SUB"] = 140] = "1SUB";
    OP[OP["2MUL"] = 141] = "2MUL";
    OP[OP["2DIV"] = 142] = "2DIV";
    OP[OP["NEGATE"] = 143] = "NEGATE";
    OP[OP["ABS"] = 144] = "ABS";
    OP[OP["NOT"] = 145] = "NOT";
    OP[OP["0NOTEQUAL"] = 146] = "0NOTEQUAL";
    OP[OP["ADD"] = 147] = "ADD";
    OP[OP["SUB"] = 148] = "SUB";
    OP[OP["MUL"] = 149] = "MUL";
    OP[OP["DIV"] = 150] = "DIV";
    OP[OP["MOD"] = 151] = "MOD";
    OP[OP["LSHIFT"] = 152] = "LSHIFT";
    OP[OP["RSHIFT"] = 153] = "RSHIFT";
    OP[OP["BOOLAND"] = 154] = "BOOLAND";
    OP[OP["BOOLOR"] = 155] = "BOOLOR";
    OP[OP["NUMEQUAL"] = 156] = "NUMEQUAL";
    OP[OP["NUMEQUALVERIFY"] = 157] = "NUMEQUALVERIFY";
    OP[OP["NUMNOTEQUAL"] = 158] = "NUMNOTEQUAL";
    OP[OP["LESSTHAN"] = 159] = "LESSTHAN";
    OP[OP["GREATERTHAN"] = 160] = "GREATERTHAN";
    OP[OP["LESSTHANOREQUAL"] = 161] = "LESSTHANOREQUAL";
    OP[OP["GREATERTHANOREQUAL"] = 162] = "GREATERTHANOREQUAL";
    OP[OP["MIN"] = 163] = "MIN";
    OP[OP["MAX"] = 164] = "MAX";
    OP[OP["WITHIN"] = 165] = "WITHIN";
    // Crypto
    OP[OP["RIPEMD160"] = 166] = "RIPEMD160";
    OP[OP["SHA1"] = 167] = "SHA1";
    OP[OP["SHA256"] = 168] = "SHA256";
    OP[OP["HASH160"] = 169] = "HASH160";
    OP[OP["HASH256"] = 170] = "HASH256";
    OP[OP["CODESEPARATOR"] = 171] = "CODESEPARATOR";
    OP[OP["CHECKSIG"] = 172] = "CHECKSIG";
    OP[OP["CHECKSIGVERIFY"] = 173] = "CHECKSIGVERIFY";
    OP[OP["CHECKMULTISIG"] = 174] = "CHECKMULTISIG";
    OP[OP["CHECKMULTISIGVERIFY"] = 175] = "CHECKMULTISIGVERIFY";
    // Expansion
    OP[OP["NOP1"] = 176] = "NOP1";
    OP[OP["CHECKLOCKTIMEVERIFY"] = 177] = "CHECKLOCKTIMEVERIFY";
    OP[OP["CHECKSEQUENCEVERIFY"] = 178] = "CHECKSEQUENCEVERIFY";
    OP[OP["NOP4"] = 179] = "NOP4";
    OP[OP["NOP5"] = 180] = "NOP5";
    OP[OP["NOP6"] = 181] = "NOP6";
    OP[OP["NOP7"] = 182] = "NOP7";
    OP[OP["NOP8"] = 183] = "NOP8";
    OP[OP["NOP9"] = 184] = "NOP9";
    OP[OP["NOP10"] = 185] = "NOP10";
    // BIP 342
    OP[OP["CHECKSIGADD"] = 186] = "CHECKSIGADD";
    // Invalid
    OP[OP["INVALID"] = 255] = "INVALID";
})(OP || (OP = {}));
// Converts script bytes to parsed script
// 5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae
// =>
// OP_2
//   030000000000000000000000000000000000000000000000000000000000000001
//   030000000000000000000000000000000000000000000000000000000000000002
//   030000000000000000000000000000000000000000000000000000000000000003
//   OP_3
//   CHECKMULTISIG
export const Script = P.wrap({
    encodeStream: (w, value) => {
        for (let o of value) {
            if (typeof o === 'string') {
                if (OP[o] === undefined)
                    throw new Error(`Unknown opcode=${o}`);
                w.byte(OP[o]);
                continue;
            }
            else if (typeof o === 'number') {
                if (o === 0x00) {
                    w.byte(0x00);
                    continue;
                }
                else if (1 <= o && o <= 16) {
                    w.byte(OP.OP_1 - 1 + o);
                    continue;
                }
            }
            // Encode big numbers
            if (typeof o === 'number')
                o = ScriptNum().encode(BigInt(o));
            if (!isBytes(o))
                throw new Error(`Wrong Script OP=${o} (${typeof o})`);
            // Bytes
            const len = o.length;
            if (len < OP.PUSHDATA1)
                w.byte(len);
            else if (len <= 0xff) {
                w.byte(OP.PUSHDATA1);
                w.byte(len);
            }
            else if (len <= 0xffff) {
                w.byte(OP.PUSHDATA2);
                w.bytes(P.U16LE.encode(len));
            }
            else {
                w.byte(OP.PUSHDATA4);
                w.bytes(P.U32LE.encode(len));
            }
            w.bytes(o);
        }
    },
    decodeStream: (r) => {
        const out = [];
        while (!r.isEnd()) {
            const cur = r.byte();
            // if 0 < cur < 78
            if (OP.OP_0 < cur && cur <= OP.PUSHDATA4) {
                let len;
                if (cur < OP.PUSHDATA1)
                    len = cur;
                else if (cur === OP.PUSHDATA1)
                    len = P.U8.decodeStream(r);
                else if (cur === OP.PUSHDATA2)
                    len = P.U16LE.decodeStream(r);
                else if (cur === OP.PUSHDATA4)
                    len = P.U32LE.decodeStream(r);
                else
                    throw new Error('Should be not possible');
                out.push(r.bytes(len));
            }
            else if (cur === 0x00) {
                out.push(0);
            }
            else if (OP.OP_1 <= cur && cur <= OP.OP_16) {
                out.push(cur - (OP.OP_1 - 1));
            }
            else {
                const op = OP[cur];
                if (op === undefined)
                    throw new Error(`Unknown opcode=${cur.toString(16)}`);
                out.push(op);
            }
        }
        return out;
    },
});
// We can encode almost any number as ScriptNum, however, parsing will be a problem
// since we can't know if buffer is a number or something else.
export function ScriptNum(bytesLimit = 6, forceMinimal = false) {
    return P.wrap({
        encodeStream: (w, value) => {
            if (value === 0n)
                return;
            const neg = value < 0;
            const val = BigInt(value);
            const nums = [];
            for (let abs = neg ? -val : val; abs; abs >>= 8n)
                nums.push(Number(abs & 0xffn));
            if (nums[nums.length - 1] >= 0x80)
                nums.push(neg ? 0x80 : 0);
            else if (neg)
                nums[nums.length - 1] |= 0x80;
            w.bytes(new Uint8Array(nums));
        },
        decodeStream: (r) => {
            const len = r.leftBytes;
            if (len > bytesLimit)
                throw new Error(`ScriptNum: number (${len}) bigger than limit=${bytesLimit}`);
            if (len === 0)
                return 0n;
            if (forceMinimal) {
                // MSB is zero (without sign bit) -> not minimally encoded
                if ((r.data[len - 1] & 0x7f) === 0) {
                    // exception
                    if (len <= 1 || (r.data[len - 2] & 0x80) === 0)
                        throw new Error('Non-minimally encoded ScriptNum');
                }
            }
            let last = 0;
            let res = 0n;
            for (let i = 0; i < len; ++i) {
                last = r.byte();
                res |= BigInt(last) << (8n * BigInt(i));
            }
            if (last >= 0x80) {
                res &= (2n ** BigInt(len * 8) - 1n) >> 1n;
                res = -res;
            }
            return res;
        },
    });
}
export function OpToNum(op, bytesLimit = 4, forceMinimal = true) {
    if (typeof op === 'number')
        return op;
    if (isBytes(op)) {
        try {
            const val = ScriptNum(bytesLimit, forceMinimal).decode(op);
            if (val > Number.MAX_SAFE_INTEGER)
                return;
            return Number(val);
        }
        catch (e) {
            return;
        }
    }
}
// BTC specific variable length integer encoding
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
const CSLimits = {
    0xfd: [0xfd, 2, 253n, 65535n],
    0xfe: [0xfe, 4, 65536n, 4294967295n],
    0xff: [0xff, 8, 4294967296n, 18446744073709551615n],
};
export const CompactSize = P.wrap({
    encodeStream: (w, value) => {
        if (typeof value === 'number')
            value = BigInt(value);
        if (0n <= value && value <= 252n)
            return w.byte(Number(value));
        for (const [flag, bytes, start, stop] of Object.values(CSLimits)) {
            if (start > value || value > stop)
                continue;
            w.byte(flag);
            for (let i = 0; i < bytes; i++)
                w.byte(Number((value >> (8n * BigInt(i))) & 0xffn));
            return;
        }
        throw w.err(`VarInt too big: ${value}`);
    },
    decodeStream: (r) => {
        const b0 = r.byte();
        if (b0 <= 0xfc)
            return BigInt(b0);
        const [_, bytes, start] = CSLimits[b0];
        let num = 0n;
        for (let i = 0; i < bytes; i++)
            num |= BigInt(r.byte()) << (8n * BigInt(i));
        if (num < start)
            throw r.err(`Wrong CompactSize(${8 * bytes})`);
        return num;
    },
});
// Same thing, but in number instead of bigint. Checks for safe integer inside
const CompactSizeLen = P.apply(CompactSize, P.coders.number);
// Array of size <CompactSize>
export const BTCArray = (t) => P.array(CompactSize, t);
// ui8a of size <CompactSize>
export const VarBytes = P.bytes(CompactSize);
export const RawInput = P.struct({
    txid: P.bytes(32, true),
    index: P.U32LE,
    finalScriptSig: VarBytes,
    sequence: P.U32LE, // ?
});
export const RawOutput = P.struct({ amount: P.U64LE, script: VarBytes });
const EMPTY_OUTPUT = {
    amount: 0xffffffffffffffffn,
    script: P.EMPTY,
};
// SegWit v0 stack of witness buffers
export const RawWitness = P.array(CompactSizeLen, VarBytes);
// https://en.bitcoin.it/wiki/Protocol_documentation#tx
const _RawTx = P.struct({
    version: P.I32LE,
    segwitFlag: P.flag(new Uint8Array([0x00, 0x01])),
    inputs: BTCArray(RawInput),
    outputs: BTCArray(RawOutput),
    witnesses: P.flagged('segwitFlag', P.array('inputs/length', RawWitness)),
    // < 500000000	Block number at which this transaction is unlocked
    // >= 500000000	UNIX timestamp at which this transaction is unlocked
    // Handled as part of PSBTv2
    lockTime: P.U32LE,
});
function validateRawTx(tx) {
    if (tx.segwitFlag && tx.witnesses && !tx.witnesses.length)
        throw new Error('Segwit flag with empty witnesses array');
    return tx;
}
export const RawTx = P.validate(_RawTx, validateRawTx);
function PSBTKeyInfo(info) {
    const [type, kc, vc, reqInc, allowInc, silentIgnore] = info;
    return { type, kc, vc, reqInc, allowInc, silentIgnore };
}
const BIP32Der = P.struct({
    fingerprint: P.U32BE,
    path: P.array(null, P.U32LE),
});
// Complex structure for PSBT fields
// <control byte with leaf version and parity bit> <internal key p> <C> <E> <AB>
const _TaprootControlBlock = P.struct({
    version: P.U8,
    internalKey: P.bytes(32),
    merklePath: P.array(null, P.bytes(32)),
});
export const TaprootControlBlock = P.validate(_TaprootControlBlock, (cb) => {
    if (cb.merklePath.length > 128)
        throw new Error('TaprootControlBlock: merklePath should be of length 0..128 (inclusive)');
    return cb;
});
const TaprootBIP32Der = P.struct({
    hashes: P.array(CompactSizeLen, P.bytes(32)),
    der: BIP32Der,
});
// The 78 byte serialized extended public key as defined by BIP 32.
const GlobalXPUB = P.bytes(78);
const tapScriptSigKey = P.struct({ pubKey: PubKeySchnorr, leafHash: P.bytes(32) });
// {<8-bit uint depth> <8-bit uint leaf version> <compact size uint scriptlen> <bytes script>}*
const tapTree = P.array(null, P.struct({
    depth: P.U8,
    version: P.U8,
    script: VarBytes,
}));
const BytesInf = P.bytes(null); // Bytes will conflict with Bytes type
const Bytes20 = P.bytes(20);
const Bytes32 = P.bytes(32);
// versionsRequiringExclusing = !versionsAllowsInclusion (as set)
// {name: [tag, keyCoder, valueCoder, versionsRequiringInclusion, versionsRequiringExclusing, versionsAllowsInclusion, silentIgnore]}
// SilentIgnore: we use some v2 fields for v1 representation too, so we just clean them before serialize
// Tables from BIP-0174 (https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
// prettier-ignore
const PSBTGlobal = {
    unsignedTx: [0x00, false, RawTx, [0], [0], false],
    xpub: [0x01, GlobalXPUB, BIP32Der, [], [0, 2], false],
    txVersion: [0x02, false, P.U32LE, [2], [2], false],
    fallbackLocktime: [0x03, false, P.U32LE, [], [2], false],
    inputCount: [0x04, false, CompactSizeLen, [2], [2], false],
    outputCount: [0x05, false, CompactSizeLen, [2], [2], false],
    txModifiable: [0x06, false, P.U8, [], [2], false],
    version: [0xfb, false, P.U32LE, [], [0, 2], false],
    proprietary: [0xfc, BytesInf, BytesInf, [], [0, 2], false],
};
// prettier-ignore
const PSBTInput = {
    nonWitnessUtxo: [0x00, false, RawTx, [], [0, 2], false],
    witnessUtxo: [0x01, false, RawOutput, [], [0, 2], false],
    partialSig: [0x02, PubKeyECDSA, BytesInf, [], [0, 2], false],
    sighashType: [0x03, false, P.U32LE, [], [0, 2], false],
    redeemScript: [0x04, false, BytesInf, [], [0, 2], false],
    witnessScript: [0x05, false, BytesInf, [], [0, 2], false],
    bip32Derivation: [0x06, PubKeyECDSA, BIP32Der, [], [0, 2], false],
    finalScriptSig: [0x07, false, BytesInf, [], [0, 2], false],
    finalScriptWitness: [0x08, false, RawWitness, [], [0, 2], false],
    porCommitment: [0x09, false, BytesInf, [], [0, 2], false],
    ripemd160: [0x0a, Bytes20, BytesInf, [], [0, 2], false],
    sha256: [0x0b, Bytes32, BytesInf, [], [0, 2], false],
    hash160: [0x0c, Bytes20, BytesInf, [], [0, 2], false],
    hash256: [0x0d, Bytes32, BytesInf, [], [0, 2], false],
    txid: [0x0e, false, Bytes32, [2], [2], true],
    index: [0x0f, false, P.U32LE, [2], [2], true],
    sequence: [0x10, false, P.U32LE, [], [2], true],
    requiredTimeLocktime: [0x11, false, P.U32LE, [], [2], false],
    requiredHeightLocktime: [0x12, false, P.U32LE, [], [2], false],
    tapKeySig: [0x13, false, SignatureSchnorr, [], [0, 2], false],
    tapScriptSig: [0x14, tapScriptSigKey, SignatureSchnorr, [], [0, 2], false],
    tapLeafScript: [0x15, TaprootControlBlock, BytesInf, [], [0, 2], false],
    tapBip32Derivation: [0x16, Bytes32, TaprootBIP32Der, [], [0, 2], false],
    tapInternalKey: [0x17, false, PubKeySchnorr, [], [0, 2], false],
    tapMerkleRoot: [0x18, false, Bytes32, [], [0, 2], false],
    proprietary: [0xfc, BytesInf, BytesInf, [], [0, 2], false],
};
// All other keys removed when finalizing
const PSBTInputFinalKeys = [
    'txid',
    'sequence',
    'index',
    'witnessUtxo',
    'nonWitnessUtxo',
    'finalScriptSig',
    'finalScriptWitness',
    'unknown',
];
// Can be modified even on signed input
const PSBTInputUnsignedKeys = [
    'partialSig',
    'finalScriptSig',
    'finalScriptWitness',
    'tapKeySig',
    'tapScriptSig',
];
// prettier-ignore
const PSBTOutput = {
    redeemScript: [0x00, false, BytesInf, [], [0, 2], false],
    witnessScript: [0x01, false, BytesInf, [], [0, 2], false],
    bip32Derivation: [0x02, PubKeyECDSA, BIP32Der, [], [0, 2], false],
    amount: [0x03, false, P.I64LE, [2], [2], true],
    script: [0x04, false, BytesInf, [2], [2], true],
    tapInternalKey: [0x05, false, PubKeySchnorr, [], [0, 2], false],
    tapTree: [0x06, false, tapTree, [], [0, 2], false],
    tapBip32Derivation: [0x07, PubKeySchnorr, TaprootBIP32Der, [], [0, 2], false],
    proprietary: [0xfc, BytesInf, BytesInf, [], [0, 2], false],
};
// Can be modified even on signed input
const PSBTOutputUnsignedKeys = [];
const PSBTKeyPair = P.array(P.NULL, P.struct({
    //  <key> := <keylen> <keytype> <keydata> WHERE keylen = len(keytype)+len(keydata)
    key: P.prefix(CompactSizeLen, P.struct({ type: CompactSizeLen, key: P.bytes(null) })),
    //  <value> := <valuelen> <valuedata>
    value: P.bytes(CompactSizeLen),
}));
const PSBTUnknownKey = P.struct({ type: CompactSizeLen, key: P.bytes(null) });
// Key cannot be 'unknown', value coder cannot be array for elements with empty key
function PSBTKeyMap(psbtEnum) {
    // -> Record<type, [keyName, ...coders]>
    const byType = {};
    for (const k in psbtEnum) {
        const [num, kc, vc] = psbtEnum[k];
        byType[num] = [k, kc, vc];
    }
    return P.wrap({
        encodeStream: (w, value) => {
            let out = [];
            // Because we use order of psbtEnum, keymap is sorted here
            for (const name in psbtEnum) {
                const val = value[name];
                if (val === undefined)
                    continue;
                const [type, kc, vc] = psbtEnum[name];
                if (!kc)
                    out.push({ key: { type, key: P.EMPTY }, value: vc.encode(val) });
                else {
                    // Low level interface, returns keys as is (with duplicates). Useful for debug
                    const kv = val.map(([k, v]) => [
                        kc.encode(k),
                        vc.encode(v),
                    ]);
                    // sort by keys
                    kv.sort((a, b) => _cmpBytes(a[0], b[0]));
                    for (const [key, value] of kv)
                        out.push({ key: { key, type }, value });
                }
            }
            if (value.unknown) {
                value.unknown.sort((a, b) => _cmpBytes(a[0].key, b[0].key));
                for (const [k, v] of value.unknown)
                    out.push({ key: k, value: v });
            }
            PSBTKeyPair.encodeStream(w, out);
        },
        decodeStream: (r) => {
            const raw = PSBTKeyPair.decodeStream(r);
            const out = {};
            const noKey = {};
            for (const elm of raw) {
                let name = 'unknown';
                let key = elm.key.key;
                let value = elm.value;
                if (byType[elm.key.type]) {
                    const [_name, kc, vc] = byType[elm.key.type];
                    name = _name;
                    if (!kc && key.length) {
                        throw new Error(`PSBT: Non-empty key for ${name} (key=${hex.encode(key)} value=${hex.encode(value)}`);
                    }
                    key = kc ? kc.decode(key) : undefined;
                    value = vc.decode(value);
                    if (!kc) {
                        if (out[name])
                            throw new Error(`PSBT: Same keys: ${name} (key=${key} value=${value})`);
                        out[name] = value;
                        noKey[name] = true;
                        continue;
                    }
                }
                else {
                    // For unknown: add key type inside key
                    key = { type: elm.key.type, key: elm.key.key };
                }
                // Only keyed elements at this point
                if (noKey[name])
                    throw new Error(`PSBT: Key type with empty key and no key=${name} val=${value}`);
                if (!out[name])
                    out[name] = [];
                out[name].push([key, value]);
            }
            return out;
        },
    });
}
// Basic sanity check for scripts
function checkWSH(s, witnessScript) {
    if (!P.equalBytes(s.hash, sha256(witnessScript)))
        throw new Error('checkScript: wsh wrong witnessScript hash');
    const w = OutScript.decode(witnessScript);
    if (w.type === 'tr' || w.type === 'tr_ns' || w.type === 'tr_ms')
        throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2SH`);
    if (w.type === 'wpkh' || w.type === 'sh')
        throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2WSH`);
}
function checkScript(script, redeemScript, witnessScript) {
    if (script) {
        const s = OutScript.decode(script);
        // ms||pk maybe work, but there will be no address, hard to spend
        if (s.type === 'tr_ns' || s.type === 'tr_ms' || s.type === 'ms' || s.type == 'pk')
            throw new Error(`checkScript: non-wrapped ${s.type}`);
        if (s.type === 'sh' && redeemScript) {
            if (!P.equalBytes(s.hash, hash160(redeemScript)))
                throw new Error('checkScript: sh wrong redeemScript hash');
            const r = OutScript.decode(redeemScript);
            if (r.type === 'tr' || r.type === 'tr_ns' || r.type === 'tr_ms')
                throw new Error(`checkScript: P2${r.type} cannot be wrapped in P2SH`);
            // Not sure if this unspendable, but we cannot represent this via PSBT
            if (r.type === 'sh')
                throw new Error('checkScript: P2SH cannot be wrapped in P2SH');
        }
        if (s.type === 'wsh' && witnessScript)
            checkWSH(s, witnessScript);
    }
    if (redeemScript) {
        const r = OutScript.decode(redeemScript);
        if (r.type === 'wsh' && witnessScript)
            checkWSH(r, witnessScript);
    }
}
const PSBTInputCoder = P.validate(PSBTKeyMap(PSBTInput), (i) => {
    if (i.finalScriptWitness && !i.finalScriptWitness.length)
        throw new Error('validateInput: wmpty finalScriptWitness');
    //if (i.finalScriptSig && !i.finalScriptSig.length) throw new Error('validateInput: empty finalScriptSig');
    if (i.partialSig && !i.partialSig.length)
        throw new Error('Empty partialSig');
    if (i.partialSig)
        for (const [k, v] of i.partialSig)
            validatePubkey(k, PubT.ecdsa);
    if (i.bip32Derivation)
        for (const [k, v] of i.bip32Derivation)
            validatePubkey(k, PubT.ecdsa);
    // Locktime = unsigned little endian integer greater than or equal to 500000000 representing
    if (i.requiredTimeLocktime !== undefined && i.requiredTimeLocktime < 500000000)
        throw new Error(`validateInput: wrong timeLocktime=${i.requiredTimeLocktime}`);
    // unsigned little endian integer greater than 0 and less than 500000000
    if (i.requiredHeightLocktime !== undefined &&
        (i.requiredHeightLocktime <= 0 || i.requiredHeightLocktime >= 500000000))
        throw new Error(`validateInput: wrong heighLocktime=${i.requiredHeightLocktime}`);
    if (i.nonWitnessUtxo && i.index !== undefined) {
        const last = i.nonWitnessUtxo.outputs.length - 1;
        if (i.index > last)
            throw new Error(`validateInput: index(${i.index}) not in nonWitnessUtxo`);
        const prevOut = i.nonWitnessUtxo.outputs[i.index];
        if (i.witnessUtxo &&
            (!P.equalBytes(i.witnessUtxo.script, prevOut.script) ||
                i.witnessUtxo.amount !== prevOut.amount))
            throw new Error('validateInput: witnessUtxo different from nonWitnessUtxo');
    }
    if (i.tapLeafScript) {
        // tap leaf version appears here twice: in control block and at the end of script
        for (const [k, v] of i.tapLeafScript) {
            if ((k.version & 254) !== v[v.length - 1])
                throw new Error('validateInput: tapLeafScript version mimatch');
            if (v[v.length - 1] & 1)
                throw new Error('validateInput: tapLeafScript version has parity bit!');
        }
    }
    // Validate txid for nonWitnessUtxo is correct
    if (i.nonWitnessUtxo && i.index && i.txid) {
        const outputs = i.nonWitnessUtxo.outputs;
        if (outputs.length - 1 < i.index)
            throw new Error('nonWitnessUtxo: incorect output index');
        const tx = Transaction.fromRaw(RawTx.encode(i.nonWitnessUtxo));
        const txid = hex.encode(i.txid);
        if (tx.id !== txid)
            throw new Error(`nonWitnessUtxo: wrong txid, exp=${txid} got=${tx.id}`);
    }
    return i;
});
const PSBTOutputCoder = P.validate(PSBTKeyMap(PSBTOutput), (o) => {
    if (o.bip32Derivation)
        for (const [k, v] of o.bip32Derivation)
            validatePubkey(k, PubT.ecdsa);
    return o;
});
const PSBTGlobalCoder = P.validate(PSBTKeyMap(PSBTGlobal), (g) => {
    const version = g.version || 0;
    if (version === 0) {
        if (!g.unsignedTx)
            throw new Error('PSBTv0: missing unsignedTx');
        if (g.unsignedTx.segwitFlag || g.unsignedTx.witnesses)
            throw new Error('PSBTv0: witness in unsingedTx');
        for (const inp of g.unsignedTx.inputs)
            if (inp.finalScriptSig && inp.finalScriptSig.length)
                throw new Error('PSBTv0: input scriptSig found in unsignedTx');
    }
    return g;
});
export const _RawPSBTV0 = P.struct({
    magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
    global: PSBTGlobalCoder,
    inputs: P.array('global/unsignedTx/inputs/length', PSBTInputCoder),
    outputs: P.array(null, PSBTOutputCoder),
});
export const _RawPSBTV2 = P.struct({
    magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
    global: PSBTGlobalCoder,
    inputs: P.array('global/inputCount', PSBTInputCoder),
    outputs: P.array('global/outputCount', PSBTOutputCoder),
});
export const _DebugPSBT = P.struct({
    magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
    items: P.array(null, P.apply(P.array(P.NULL, P.tuple([P.hex(CompactSizeLen), P.bytes(CompactSize)])), P.coders.dict())),
});
function validatePSBTFields(version, info, lst) {
    for (const k in lst) {
        if (k === 'unknown')
            continue;
        if (!info[k])
            continue;
        const { allowInc } = PSBTKeyInfo(info[k]);
        if (!allowInc.includes(version))
            throw new Error(`PSBTv${version}: field ${k} is not allowed`);
    }
    for (const k in info) {
        const { reqInc } = PSBTKeyInfo(info[k]);
        if (reqInc.includes(version) && lst[k] === undefined)
            throw new Error(`PSBTv${version}: missing required field ${k}`);
    }
}
function cleanPSBTFields(version, info, lst) {
    const out = {};
    for (const _k in lst) {
        const k = _k;
        if (k !== 'unknown') {
            if (!info[k])
                continue;
            const { allowInc, silentIgnore } = PSBTKeyInfo(info[k]);
            if (!allowInc.includes(version)) {
                if (silentIgnore)
                    continue;
                throw new Error(`Failed to serialize in PSBTv${version}: ${k} but versions allows inclusion=${allowInc}`);
            }
        }
        out[k] = lst[k];
    }
    return out;
}
function validatePSBT(tx) {
    const version = (tx && tx.global && tx.global.version) || 0;
    validatePSBTFields(version, PSBTGlobal, tx.global);
    for (const i of tx.inputs)
        validatePSBTFields(version, PSBTInput, i);
    for (const o of tx.outputs)
        validatePSBTFields(version, PSBTOutput, o);
    // We allow only one empty element at the end of map (compat with bitcoinjs-lib bug)
    const inputCount = !version ? tx.global.unsignedTx.inputs.length : tx.global.inputCount;
    if (tx.inputs.length < inputCount)
        throw new Error('Not enough inputs');
    const inputsLeft = tx.inputs.slice(inputCount);
    if (inputsLeft.length > 1 || (inputsLeft.length && Object.keys(inputsLeft[0]).length))
        throw new Error(`Unexpected inputs left in tx=${inputsLeft}`);
    // Same for inputs
    const outputCount = !version ? tx.global.unsignedTx.outputs.length : tx.global.outputCount;
    if (tx.outputs.length < outputCount)
        throw new Error('Not outputs inputs');
    const outputsLeft = tx.outputs.slice(outputCount);
    if (outputsLeft.length > 1 || (outputsLeft.length && Object.keys(outputsLeft[0]).length))
        throw new Error(`Unexpected outputs left in tx=${outputsLeft}`);
    return tx;
}
function mergeKeyMap(psbtEnum, val, cur, allowedFields) {
    const res = { ...cur, ...val };
    // All arguments can be provided as hex
    for (const k in psbtEnum) {
        const key = k;
        const [_, kC, vC] = psbtEnum[key];
        const cannotChange = allowedFields && !allowedFields.includes(k);
        if (val[k] === undefined && k in val) {
            if (cannotChange)
                throw new Error(`Cannot remove signed field=${k}`);
            delete res[k];
        }
        else if (kC) {
            const oldKV = (cur && cur[k] ? cur[k] : []);
            let newKV = val[key];
            if (newKV) {
                if (!Array.isArray(newKV))
                    throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
                // Decode hex in k-v
                newKV = newKV.map((val) => {
                    if (val.length !== 2)
                        throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
                    return [
                        typeof val[0] === 'string' ? kC.decode(hex.decode(val[0])) : val[0],
                        typeof val[1] === 'string' ? vC.decode(hex.decode(val[1])) : val[1],
                    ];
                });
                const map = {};
                const add = (kStr, k, v) => {
                    if (map[kStr] === undefined) {
                        map[kStr] = [k, v];
                        return;
                    }
                    const oldVal = hex.encode(vC.encode(map[kStr][1]));
                    const newVal = hex.encode(vC.encode(v));
                    if (oldVal !== newVal)
                        throw new Error(`keyMap(${key}): same key=${kStr} oldVal=${oldVal} newVal=${newVal}`);
                };
                for (const [k, v] of oldKV) {
                    const kStr = hex.encode(kC.encode(k));
                    add(kStr, k, v);
                }
                for (const [k, v] of newKV) {
                    const kStr = hex.encode(kC.encode(k));
                    // undefined removes previous value
                    if (v === undefined) {
                        if (cannotChange)
                            throw new Error(`Cannot remove signed field=${key}/${k}`);
                        delete map[kStr];
                    }
                    else
                        add(kStr, k, v);
                }
                res[key] = Object.values(map);
            }
        }
        else if (typeof res[k] === 'string') {
            res[k] = vC.decode(hex.decode(res[k]));
        }
        else if (cannotChange && k in val && cur && cur[k] !== undefined) {
            if (!P.equalBytes(vC.encode(val[k]), vC.encode(cur[k])))
                throw new Error(`Cannot change signed field=${k}`);
        }
    }
    // Remove unknown keys
    for (const k in res)
        if (!psbtEnum[k])
            delete res[k];
    return res;
}
export const RawPSBTV0 = P.validate(_RawPSBTV0, validatePSBT);
export const RawPSBTV2 = P.validate(_RawPSBTV2, validatePSBT);
// (TxHash, Idx)
const TxHashIdx = P.struct({ txid: P.bytes(32, true), index: P.U32LE });
const OutPK = {
    encode(from) {
        if (from.length !== 2 ||
            !isBytes(from[0]) ||
            !isValidPubkey(from[0], PubT.ecdsa) ||
            from[1] !== 'CHECKSIG')
            return;
        return { type: 'pk', pubkey: from[0] };
    },
    decode: (to) => (to.type === 'pk' ? [to.pubkey, 'CHECKSIG'] : undefined),
};
export const p2pk = (pubkey, network = NETWORK) => {
    if (!isValidPubkey(pubkey, PubT.ecdsa))
        throw new Error('P2PK: invalid publicKey');
    return {
        type: 'pk',
        script: OutScript.encode({ type: 'pk', pubkey }),
    };
};
const OutPKH = {
    encode(from) {
        if (from.length !== 5 || from[0] !== 'DUP' || from[1] !== 'HASH160' || !isBytes(from[2]))
            return;
        if (from[3] !== 'EQUALVERIFY' || from[4] !== 'CHECKSIG')
            return;
        return { type: 'pkh', hash: from[2] };
    },
    decode: (to) => to.type === 'pkh' ? ['DUP', 'HASH160', to.hash, 'EQUALVERIFY', 'CHECKSIG'] : undefined,
};
export const p2pkh = (publicKey, network = NETWORK) => {
    if (!isValidPubkey(publicKey, PubT.ecdsa))
        throw new Error('P2PKH: invalid publicKey');
    const hash = hash160(publicKey);
    return {
        type: 'pkh',
        script: OutScript.encode({ type: 'pkh', hash }),
        address: Address(network).encode({ type: 'pkh', hash }),
    };
};
const OutSH = {
    encode(from) {
        if (from.length !== 3 || from[0] !== 'HASH160' || !isBytes(from[1]) || from[2] !== 'EQUAL')
            return;
        return { type: 'sh', hash: from[1] };
    },
    decode: (to) => to.type === 'sh' ? ['HASH160', to.hash, 'EQUAL'] : undefined,
};
export const p2sh = (child, network = NETWORK) => {
    // It is already tested inside noble-hashes and checkScript
    const cs = child.script;
    if (!isBytes(cs))
        throw new Error(`Wrong script: ${typeof child.script}, expected Uint8Array`);
    const hash = hash160(cs);
    const script = OutScript.encode({ type: 'sh', hash });
    checkScript(script, cs, child.witnessScript);
    const res = {
        type: 'sh',
        redeemScript: cs,
        script: OutScript.encode({ type: 'sh', hash }),
        address: Address(network).encode({ type: 'sh', hash }),
    };
    if (child.witnessScript)
        res.witnessScript = child.witnessScript;
    return res;
};
const OutWSH = {
    encode(from) {
        if (from.length !== 2 || from[0] !== 0 || !isBytes(from[1]))
            return;
        if (from[1].length !== 32)
            return;
        return { type: 'wsh', hash: from[1] };
    },
    decode: (to) => (to.type === 'wsh' ? [0, to.hash] : undefined),
};
export const p2wsh = (child, network = NETWORK) => {
    const cs = child.script;
    if (!isBytes(cs))
        throw new Error(`Wrong script: ${typeof cs}, expected Uint8Array`);
    const hash = sha256(cs);
    const script = OutScript.encode({ type: 'wsh', hash });
    checkScript(script, undefined, cs);
    return {
        type: 'wsh',
        witnessScript: cs,
        script: OutScript.encode({ type: 'wsh', hash }),
        address: Address(network).encode({ type: 'wsh', hash }),
    };
};
const OutWPKH = {
    encode(from) {
        if (from.length !== 2 || from[0] !== 0 || !isBytes(from[1]))
            return;
        if (from[1].length !== 20)
            return;
        return { type: 'wpkh', hash: from[1] };
    },
    decode: (to) => (to.type === 'wpkh' ? [0, to.hash] : undefined),
};
export const p2wpkh = (publicKey, network = NETWORK) => {
    if (!isValidPubkey(publicKey, PubT.ecdsa))
        throw new Error('P2WPKH: invalid publicKey');
    if (publicKey.length === 65)
        throw new Error('P2WPKH: uncompressed public key');
    const hash = hash160(publicKey);
    return {
        type: 'wpkh',
        script: OutScript.encode({ type: 'wpkh', hash }),
        address: Address(network).encode({ type: 'wpkh', hash }),
    };
};
const OutMS = {
    encode(from) {
        const last = from.length - 1;
        if (from[last] !== 'CHECKMULTISIG')
            return;
        const m = from[0];
        const n = from[last - 1];
        if (typeof m !== 'number' || typeof n !== 'number')
            return;
        const pubkeys = from.slice(1, -2);
        if (n !== pubkeys.length)
            return;
        for (const pub of pubkeys)
            if (!isBytes(pub))
                return;
        return { type: 'ms', m, pubkeys: pubkeys }; // we don't need n, since it is the same as pubkeys
    },
    // checkmultisig(n, ..pubkeys, m)
    decode: (to) => to.type === 'ms' ? [to.m, ...to.pubkeys, to.pubkeys.length, 'CHECKMULTISIG'] : undefined,
};
export const p2ms = (m, pubkeys, allowSamePubkeys = false) => {
    if (!allowSamePubkeys)
        uniqPubkey(pubkeys);
    return { type: 'ms', script: OutScript.encode({ type: 'ms', pubkeys, m }) };
};
const OutTR = {
    encode(from) {
        if (from.length !== 2 || from[0] !== 1 || !isBytes(from[1]))
            return;
        return { type: 'tr', pubkey: from[1] };
    },
    decode: (to) => (to.type === 'tr' ? [1, to.pubkey] : undefined),
};
// Helper for generating binary tree from list, with weights
export function taprootListToTree(taprootList) {
    // Clone input in order to not corrupt it
    const lst = Array.from(taprootList);
    // We have at least 2 elements => can create branch
    while (lst.length >= 2) {
        // Sort: elements with smallest weight are in the end of queue
        lst.sort((a, b) => (b.weight || 1) - (a.weight || 1));
        const b = lst.pop();
        const a = lst.pop();
        const weight = (a?.weight || 1) + (b?.weight || 1);
        lst.push({
            weight,
            // Unwrap children array
            // TODO: Very hard to remove any here
            childs: [a?.childs || a, b?.childs || b],
        });
    }
    // At this point there is always 1 element in lst
    const last = lst[0];
    return (last?.childs || last);
}
function checkTaprootScript(script, allowUnknowOutput = false) {
    const out = OutScript.decode(script);
    if (out.type === 'unknown' && allowUnknowOutput)
        return;
    if (!['tr_ns', 'tr_ms'].includes(out.type))
        throw new Error(`P2TR: invalid leaf script=${out.type}`);
}
function taprootHashTree(tree, allowUnknowOutput = false) {
    if (!tree)
        throw new Error('taprootHashTree: empty tree');
    if (Array.isArray(tree) && tree.length === 1)
        tree = tree[0];
    // Terminal node (leaf)
    if (!Array.isArray(tree)) {
        const { leafVersion: version, script: leafScript, tapInternalKey } = tree;
        // Earliest tree walk where we can validate tapScripts
        if (tree.tapLeafScript || (tree.tapMerkleRoot && !P.equalBytes(tree.tapMerkleRoot, P.EMPTY)))
            throw new Error('P2TR: tapRoot leafScript cannot have tree');
        // Just to be sure that it is spendable
        if (tapInternalKey && P.equalBytes(tapInternalKey, TAPROOT_UNSPENDABLE_KEY))
            throw new Error('P2TR: tapRoot leafScript cannot have unspendble key');
        const script = typeof leafScript === 'string' ? hex.decode(leafScript) : leafScript;
        if (!isBytes(script))
            throw new Error(`checkScript: wrong script type=${script}`);
        checkTaprootScript(script, allowUnknowOutput);
        return {
            type: 'leaf',
            tapInternalKey,
            version,
            script,
            hash: tapLeafHash(script, version),
        };
    }
    // If tree / branch is not binary tree, convert it
    if (tree.length !== 2)
        tree = taprootListToTree(tree);
    if (tree.length !== 2)
        throw new Error('hashTree: non binary tree!');
    // branch
    // Both nodes should exist
    const left = taprootHashTree(tree[0], allowUnknowOutput);
    const right = taprootHashTree(tree[1], allowUnknowOutput);
    // We cannot swap left/right here, since it will change structure of tree
    let [lH, rH] = [left.hash, right.hash];
    if (_cmpBytes(rH, lH) === -1)
        [lH, rH] = [rH, lH];
    return { type: 'branch', left, right, hash: schnorr.utils.taggedHash('TapBranch', lH, rH) };
}
function taprootAddPath(tree, path = []) {
    if (!tree)
        throw new Error(`taprootAddPath: empty tree`);
    if (tree.type === 'leaf')
        return { ...tree, path };
    if (tree.type !== 'branch')
        throw new Error(`taprootAddPath: wrong type=${tree}`);
    return {
        ...tree,
        path,
        // Left element has right hash in path and otherwise
        left: taprootAddPath(tree.left, [tree.right.hash, ...path]),
        right: taprootAddPath(tree.right, [tree.left.hash, ...path]),
    };
}
function taprootWalkTree(tree) {
    if (!tree)
        throw new Error(`taprootAddPath: empty tree`);
    if (tree.type === 'leaf')
        return [tree];
    if (tree.type !== 'branch')
        throw new Error(`taprootWalkTree: wrong type=${tree}`);
    return [...taprootWalkTree(tree.left), ...taprootWalkTree(tree.right)];
}
// Another stupid decision, where lack of standard affects security.
// Multisig needs to be generated with some key.
// We are using approach from BIP 341/bitcoinjs-lib: SHA256(uncompressedDER(SECP256K1_GENERATOR_POINT))
// It is possible to switch SECP256K1_GENERATOR_POINT with some random point;
// but it's too complex to prove.
// Also used by bitcoin-core and bitcoinjs-lib
export const TAPROOT_UNSPENDABLE_KEY = sha256(ProjPoint.BASE.toRawBytes(false));
// Works as key OR tree.
// If we only have tree, need to add unspendable key, otherwise
// complex multisig wallet can be spent by owner of key only. See TAPROOT_UNSPENDABLE_KEY
export function p2tr(internalPubKey, tree, network = NETWORK, allowUnknowOutput = false) {
    // Unspendable
    if (!internalPubKey && !tree)
        throw new Error('p2tr: should have pubKey or scriptTree (or both)');
    const pubKey = typeof internalPubKey === 'string'
        ? hex.decode(internalPubKey)
        : internalPubKey || TAPROOT_UNSPENDABLE_KEY;
    if (!isValidPubkey(pubKey, PubT.schnorr))
        throw new Error('p2tr: non-schnorr pubkey');
    let hashedTree = tree ? taprootAddPath(taprootHashTree(tree, allowUnknowOutput)) : undefined;
    const tapMerkleRoot = hashedTree ? hashedTree.hash : undefined;
    const [tweakedPubkey, parity] = taprootTweakPubkey(pubKey, tapMerkleRoot || P.EMPTY);
    let leaves;
    if (hashedTree) {
        leaves = taprootWalkTree(hashedTree).map((l) => ({
            ...l,
            controlBlock: TaprootControlBlock.encode({
                version: (l.version || TAP_LEAF_VERSION) + parity,
                internalKey: l.tapInternalKey || pubKey,
                merklePath: l.path,
            }),
        }));
    }
    let tapLeafScript;
    if (leaves) {
        tapLeafScript = leaves.map((l) => [
            TaprootControlBlock.decode(l.controlBlock),
            concat(l.script, new Uint8Array([l.version || TAP_LEAF_VERSION])),
        ]);
    }
    const res = {
        type: 'tr',
        script: OutScript.encode({ type: 'tr', pubkey: tweakedPubkey }),
        address: Address(network).encode({ type: 'tr', pubkey: tweakedPubkey }),
        // For tests
        tweakedPubkey,
        // PSBT stuff
        tapInternalKey: pubKey,
    };
    // Just in case someone would want to select a specific script
    if (leaves)
        res.leaves = leaves;
    if (tapLeafScript)
        res.tapLeafScript = tapLeafScript;
    if (tapMerkleRoot)
        res.tapMerkleRoot = tapMerkleRoot;
    return res;
}
const OutTRNS = {
    encode(from) {
        const last = from.length - 1;
        if (from[last] !== 'CHECKSIG')
            return;
        const pubkeys = [];
        // On error return, since it can be different script
        for (let i = 0; i < last; i++) {
            const elm = from[i];
            if (i & 1) {
                if (elm !== 'CHECKSIGVERIFY' || i === last - 1)
                    return;
                continue;
            }
            if (!isBytes(elm))
                return;
            pubkeys.push(elm);
        }
        return { type: 'tr_ns', pubkeys };
    },
    decode: (to) => {
        if (to.type !== 'tr_ns')
            return;
        const out = [];
        for (let i = 0; i < to.pubkeys.length - 1; i++)
            out.push(to.pubkeys[i], 'CHECKSIGVERIFY');
        out.push(to.pubkeys[to.pubkeys.length - 1], 'CHECKSIG');
        return out;
    },
};
// Returns all combinations of size M from lst
export function combinations(m, list) {
    const res = [];
    if (!Array.isArray(list))
        throw new Error('combinations: lst arg should be array');
    const n = list.length;
    if (m > n)
        throw new Error('combinations: m > lst.length, no combinations possible');
    /*
    Basically works as M nested loops like:
    for (;idx[0]<lst.length;idx[0]++) for (idx[1]=idx[0]+1;idx[1]<lst.length;idx[1]++)
    but since we cannot create nested loops dynamically, we unroll it to a single loop
    */
    const idx = Array.from({ length: m }, (_, i) => i);
    const last = idx.length - 1;
    main: for (;;) {
        res.push(idx.map((i) => list[i]));
        idx[last] += 1;
        let i = last;
        // Propagate increment
        // idx[i] cannot be bigger than n-m+i, otherwise last elements in right part will overflow
        for (; i >= 0 && idx[i] > n - m + i; i--) {
            idx[i] = 0;
            // Overflow in idx[0], break
            if (i === 0)
                break main;
            idx[i - 1] += 1;
        }
        // Propagate: idx[i+1] = idx[idx]+1
        for (i += 1; i < idx.length; i++)
            idx[i] = idx[i - 1] + 1;
    }
    return res;
}
/**
 * M-of-N multi-leaf wallet via p2tr_ns. If m == n, single script is emitted.
 * Takes O(n^2) if m != n. 99-of-100 is ok, 5-of-100 is not.
 * `2-of-[A,B,C] => [A,B] | [A,C] | [B,C]`
 */
export const p2tr_ns = (m, pubkeys, allowSamePubkeys = false) => {
    if (!allowSamePubkeys)
        uniqPubkey(pubkeys);
    return combinations(m, pubkeys).map((i) => ({
        type: 'tr_ns',
        script: OutScript.encode({ type: 'tr_ns', pubkeys: i }),
    }));
};
// Taproot public key (case of p2tr_ns)
export const p2tr_pk = (pubkey) => p2tr_ns(1, [pubkey], undefined)[0];
const OutTRMS = {
    encode(from) {
        const last = from.length - 1;
        if (from[last] !== 'NUMEQUAL' || from[1] !== 'CHECKSIG')
            return;
        const pubkeys = [];
        const m = OpToNum(from[last - 1]);
        if (typeof m !== 'number')
            return;
        for (let i = 0; i < last - 1; i++) {
            const elm = from[i];
            if (i & 1) {
                if (elm !== (i === 1 ? 'CHECKSIG' : 'CHECKSIGADD'))
                    throw new Error('OutScript.encode/tr_ms: wrong element');
                continue;
            }
            if (!isBytes(elm))
                throw new Error('OutScript.encode/tr_ms: wrong key element');
            pubkeys.push(elm);
        }
        return { type: 'tr_ms', pubkeys, m };
    },
    decode: (to) => {
        if (to.type !== 'tr_ms')
            return;
        const out = [to.pubkeys[0], 'CHECKSIG'];
        for (let i = 1; i < to.pubkeys.length; i++)
            out.push(to.pubkeys[i], 'CHECKSIGADD');
        out.push(to.m, 'NUMEQUAL');
        return out;
    },
};
export function p2tr_ms(m, pubkeys, allowSamePubkeys = false) {
    if (!allowSamePubkeys)
        uniqPubkey(pubkeys);
    return {
        type: 'tr_ms',
        script: OutScript.encode({ type: 'tr_ms', pubkeys, m }),
    };
}
const OutUnknown = {
    encode(from) {
        return { type: 'unknown', script: Script.encode(from) };
    },
    decode: (to) => to.type === 'unknown' ? Script.decode(to.script) : undefined,
};
// /Payments
const OutScripts = [
    OutPK,
    OutPKH,
    OutSH,
    OutWSH,
    OutWPKH,
    OutMS,
    OutTR,
    OutTRNS,
    OutTRMS,
    OutUnknown,
];
// TODO: we can support user supplied output scripts now
// - addOutScript
// - removeOutScript
// - We can do that as log we modify array in-place
// - Actually is very hard, since there is sign/finalize logic
const _OutScript = P.apply(Script, P.coders.match(OutScripts));
// We can validate this once, because of packed & coders
export const OutScript = P.validate(_OutScript, (i) => {
    if (i.type === 'pk' && !isValidPubkey(i.pubkey, PubT.ecdsa))
        throw new Error('OutScript/pk: wrong key');
    if ((i.type === 'pkh' || i.type === 'sh' || i.type === 'wpkh') &&
        (!isBytes(i.hash) || i.hash.length !== 20))
        throw new Error(`OutScript/${i.type}: wrong hash`);
    if (i.type === 'wsh' && (!isBytes(i.hash) || i.hash.length !== 32))
        throw new Error(`OutScript/wsh: wrong hash`);
    if (i.type === 'tr' && (!isBytes(i.pubkey) || !isValidPubkey(i.pubkey, PubT.schnorr)))
        throw new Error('OutScript/tr: wrong taproot public key');
    if (i.type === 'ms' || i.type === 'tr_ns' || i.type === 'tr_ms')
        if (!Array.isArray(i.pubkeys))
            throw new Error('OutScript/multisig: wrong pubkeys array');
    if (i.type === 'ms') {
        const n = i.pubkeys.length;
        for (const p of i.pubkeys)
            if (!isValidPubkey(p, PubT.ecdsa))
                throw new Error('OutScript/multisig: wrong pubkey');
        if (i.m <= 0 || n > 16 || i.m > n)
            throw new Error('OutScript/multisig: invalid params');
    }
    if (i.type === 'tr_ns' || i.type === 'tr_ms') {
        for (const p of i.pubkeys)
            if (!isValidPubkey(p, PubT.schnorr))
                throw new Error(`OutScript/${i.type}: wrong pubkey`);
    }
    if (i.type === 'tr_ms') {
        const n = i.pubkeys.length;
        if (i.m <= 0 || n > 999 || i.m > n)
            throw new Error('OutScript/tr_ms: invalid params');
    }
    return i;
});
// Address
function validateWitness(version, data) {
    if (data.length < 2 || data.length > 40)
        throw new Error('Witness: invalid length');
    if (version > 16)
        throw new Error('Witness: invalid version');
    if (version === 0 && !(data.length === 20 || data.length === 32))
        throw new Error('Witness: invalid length for version');
}
export function programToWitness(version, data, network = NETWORK) {
    validateWitness(version, data);
    const coder = version === 0 ? bech32 : bech32m;
    return coder.encode(network.bech32, [version].concat(coder.toWords(data)));
}
function formatKey(hashed, prefix) {
    return base58check.encode(concat(Uint8Array.from(prefix), hashed));
}
export function WIF(network = NETWORK) {
    return {
        encode(privKey) {
            const compressed = concat(privKey, new Uint8Array([0x01]));
            return formatKey(compressed.subarray(0, 33), [network.wif]);
        },
        decode(wif) {
            let parsed = base58check.decode(wif);
            if (parsed[0] !== network.wif)
                throw new Error('Wrong WIF prefix');
            parsed = parsed.subarray(1);
            // Check what it is. Compressed flag?
            if (parsed.length !== 33)
                throw new Error('Wrong WIF length');
            if (parsed[32] !== 0x01)
                throw new Error('Wrong WIF postfix');
            return parsed.subarray(0, -1);
        },
    };
}
// Returns OutType, which can be used to create outscript
export function Address(network = NETWORK) {
    return {
        encode(from) {
            const { type } = from;
            if (type === 'wpkh')
                return programToWitness(0, from.hash, network);
            else if (type === 'wsh')
                return programToWitness(0, from.hash, network);
            else if (type === 'tr')
                return programToWitness(1, from.pubkey, network);
            else if (type === 'pkh')
                return formatKey(from.hash, [network.pubKeyHash]);
            else if (type === 'sh')
                return formatKey(from.hash, [network.scriptHash]);
            throw new Error(`Unknown address type=${type}`);
        },
        decode(address) {
            if (address.length < 14 || address.length > 74)
                throw new Error('Invalid address length');
            // Bech32
            if (network.bech32 && address.toLowerCase().startsWith(network.bech32)) {
                let res;
                try {
                    res = bech32.decode(address);
                    if (res.words[0] !== 0)
                        throw new Error(`bech32: wrong version=${res.words[0]}`);
                }
                catch (_) {
                    // Starting from version 1 it is decoded as bech32m
                    res = bech32m.decode(address);
                    if (res.words[0] === 0)
                        throw new Error(`bech32m: wrong version=${res.words[0]}`);
                }
                if (res.prefix !== network.bech32)
                    throw new Error(`wrong bech32 prefix=${res.prefix}`);
                const [version, ...program] = res.words;
                const data = bech32.fromWords(program);
                validateWitness(version, data);
                if (version === 0 && data.length === 32)
                    return { type: 'wsh', hash: data };
                else if (version === 0 && data.length === 20)
                    return { type: 'wpkh', hash: data };
                else if (version === 1 && data.length === 32)
                    return { type: 'tr', pubkey: data };
                else
                    throw new Error('Unkown witness program');
            }
            const data = base58.decode(address);
            if (data.length !== 25)
                throw new Error('Invalid base58 address');
            // Pay To Public Key Hash
            if (data[0] === network.pubKeyHash) {
                const bytes = base58.decode(address);
                return { type: 'pkh', hash: bytes.slice(1, bytes.length - 4) };
            }
            else if (data[0] === network.scriptHash) {
                const bytes = base58.decode(address);
                return {
                    type: 'sh',
                    hash: base58.decode(address).slice(1, bytes.length - 4),
                };
            }
            throw new Error(`Invalid address prefix=${data[0]}`);
        },
    };
}
// /Address
export var SignatureHash;
(function (SignatureHash) {
    SignatureHash[SignatureHash["DEFAULT"] = 0] = "DEFAULT";
    SignatureHash[SignatureHash["ALL"] = 1] = "ALL";
    SignatureHash[SignatureHash["NONE"] = 2] = "NONE";
    SignatureHash[SignatureHash["SINGLE"] = 3] = "SINGLE";
    SignatureHash[SignatureHash["ANYONECANPAY"] = 128] = "ANYONECANPAY";
})(SignatureHash || (SignatureHash = {}));
export const SigHashCoder = P.apply(P.U32LE, P.coders.tsEnum(SignatureHash));
function unpackSighash(hashType) {
    const masked = hashType & 0b0011111;
    return {
        isAny: !!(hashType & SignatureHash.ANYONECANPAY),
        isNone: masked === SignatureHash.NONE,
        isSingle: masked === SignatureHash.SINGLE,
    };
}
export const _sortPubkeys = (pubkeys) => Array.from(pubkeys).sort(_cmpBytes);
// Force check index/txid/sequence
function inputBeforeSign(i) {
    if (i.txid === undefined || i.index === undefined)
        throw new Error('Transaction/input: txid and index required');
    return {
        txid: i.txid,
        index: i.index,
        sequence: def(i.sequence, DEFAULT_SEQUENCE),
        finalScriptSig: def(i.finalScriptSig, P.EMPTY),
    };
}
function cleanFinalInput(i) {
    for (const _k in i) {
        const k = _k;
        if (!PSBTInputFinalKeys.includes(k))
            delete i[k];
    }
}
// Force check amount/script
function outputBeforeSign(i) {
    if (i.script === undefined || i.amount === undefined)
        throw new Error('Transaction/output: script and amount required');
    return { script: i.script, amount: i.amount };
}
export const TAP_LEAF_VERSION = 0xc0;
export const tapLeafHash = (script, version = TAP_LEAF_VERSION) => schnorr.utils.taggedHash('TapLeaf', new Uint8Array([version]), VarBytes.encode(script));
function getTaprootKeys(privKey, pubKey, internalKey, merkleRoot = P.EMPTY) {
    if (P.equalBytes(internalKey, pubKey)) {
        privKey = taprootTweakPrivKey(privKey, merkleRoot);
        pubKey = schnorr.getPublicKey(privKey);
    }
    return { privKey, pubKey };
}
// Check if object doens't have custom constructor (like Uint8Array/Array)
const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
function validateOpts(opts) {
    if (!isPlainObject(opts))
        throw new Error(`Wrong object type for transaction options: ${opts}`);
    const _opts = {
        ...opts,
        version: def(opts.version, DEFAULT_VERSION),
        lockTime: def(opts.lockTime, 0),
        PSBTVersion: def(opts.PSBTVersion, 0),
    }; // Defaults
    // 0 and -1 happens in tests
    if (![-1, 0, 1, 2].includes(_opts.version))
        throw new Error(`Unknown version: ${_opts.version}`);
    if (typeof _opts.lockTime !== 'number')
        throw new Error('Transaction lock time should be number');
    P.U32LE.encode(_opts.lockTime); // Additional range checks that lockTime
    // There is no PSBT v1, and any new version will probably have fields which we don't know how to parse, which
    // can lead to constructing broken transactions
    if (_opts.PSBTVersion !== 0 && _opts.PSBTVersion !== 2)
        throw new Error(`Unknown PSBT version ${_opts.PSBTVersion}`);
    // Flags
    for (const k of [
        'allowUnknowOutput',
        'allowUnknowInput',
        'disableScriptCheck',
        'bip174jsCompat',
        'allowLegacyWitnessUtxo',
        'lowR',
    ]) {
        const v = _opts[k];
        if (v === undefined)
            continue; // optional
        if (typeof v !== 'boolean')
            throw new Error(`Transation options wrong type: ${k}=${v} (${typeof v})`);
    }
    return Object.freeze(_opts);
}
export class Transaction {
    constructor(opts = {}) {
        this.global = {};
        this.inputs = []; // use getInput()
        this.outputs = []; // use getOutput()
        const _opts = (this.opts = validateOpts(opts));
        // Merge with global structure of PSBTv2
        if (_opts.lockTime !== DEFAULT_LOCKTIME)
            this.global.fallbackLocktime = _opts.lockTime;
        this.global.txVersion = _opts.version;
    }
    // Import
    static fromRaw(raw, opts = {}) {
        const parsed = RawTx.decode(raw);
        const tx = new Transaction({ ...opts, version: parsed.version, lockTime: parsed.lockTime });
        for (const o of parsed.outputs)
            tx.addOutput(o);
        tx.outputs = parsed.outputs;
        tx.inputs = parsed.inputs;
        if (parsed.witnesses) {
            for (let i = 0; i < parsed.witnesses.length; i++)
                tx.inputs[i].finalScriptWitness = parsed.witnesses[i];
        }
        return tx;
    }
    // PSBT
    static fromPSBT(psbt, opts = {}) {
        let parsed;
        try {
            parsed = RawPSBTV0.decode(psbt);
        }
        catch (e0) {
            try {
                parsed = RawPSBTV2.decode(psbt);
            }
            catch (e2) {
                // Throw error for v0 parsing, since it popular, otherwise it would be shadowed by v2 error
                throw e0;
            }
        }
        const PSBTVersion = parsed.global.version || 0;
        if (PSBTVersion !== 0 && PSBTVersion !== 2)
            throw new Error(`Wrong PSBT version=${PSBTVersion}`);
        const unsigned = parsed.global.unsignedTx;
        const version = PSBTVersion === 0 ? unsigned?.version : parsed.global.txVersion;
        const lockTime = PSBTVersion === 0 ? unsigned?.lockTime : parsed.global.fallbackLocktime;
        const tx = new Transaction({ ...opts, version, lockTime, PSBTVersion });
        // We need slice here, because otherwise
        const inputCount = PSBTVersion === 0 ? unsigned?.inputs.length : parsed.global.inputCount;
        tx.inputs = parsed.inputs.slice(0, inputCount).map((i, j) => ({
            finalScriptSig: P.EMPTY,
            ...parsed.global.unsignedTx?.inputs[j],
            ...i,
        }));
        const outputCount = PSBTVersion === 0 ? unsigned?.outputs.length : parsed.global.outputCount;
        tx.outputs = parsed.outputs.slice(0, outputCount).map((i, j) => ({
            ...i,
            ...parsed.global.unsignedTx?.outputs[j],
        }));
        tx.global = { ...parsed.global, txVersion: version }; // just in case proprietary/unknown fields
        if (lockTime !== DEFAULT_LOCKTIME)
            tx.global.fallbackLocktime = lockTime;
        return tx;
    }
    toPSBT(PSBTVersion = this.opts.PSBTVersion) {
        if (PSBTVersion !== 0 && PSBTVersion !== 2)
            throw new Error(`Wrong PSBT version=${PSBTVersion}`);
        const inputs = this.inputs.map((i) => cleanPSBTFields(PSBTVersion, PSBTInput, i));
        for (const inp of inputs) {
            // Don't serialize empty fields
            if (inp.partialSig && !inp.partialSig.length)
                delete inp.partialSig;
            if (inp.finalScriptSig && !inp.finalScriptSig.length)
                delete inp.finalScriptSig;
            if (inp.finalScriptWitness && !inp.finalScriptWitness.length)
                delete inp.finalScriptWitness;
        }
        const outputs = this.outputs.map((i) => cleanPSBTFields(PSBTVersion, PSBTOutput, i));
        const global = { ...this.global };
        if (PSBTVersion === 0) {
            global.unsignedTx = RawTx.decode(this.unsignedTx);
            delete global.fallbackLocktime;
            delete global.txVersion;
        }
        else {
            global.version = PSBTVersion;
            global.txVersion = this.version;
            global.inputCount = this.inputs.length;
            global.outputCount = this.outputs.length;
            if (global.fallbackLocktime && global.fallbackLocktime === DEFAULT_LOCKTIME)
                delete global.fallbackLocktime;
        }
        if (this.opts.bip174jsCompat) {
            if (!inputs.length)
                inputs.push({});
            if (!outputs.length)
                outputs.push({});
        }
        return (PSBTVersion === 0 ? RawPSBTV0 : RawPSBTV2).encode({
            global,
            inputs,
            outputs,
        });
    }
    // BIP370 lockTime (https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time)
    get lockTime() {
        let height = DEFAULT_LOCKTIME;
        let heightCnt = 0;
        let time = DEFAULT_LOCKTIME;
        let timeCnt = 0;
        for (const i of this.inputs) {
            if (i.requiredHeightLocktime) {
                height = Math.max(height, i.requiredHeightLocktime);
                heightCnt++;
            }
            if (i.requiredTimeLocktime) {
                time = Math.max(time, i.requiredTimeLocktime);
                timeCnt++;
            }
        }
        if (heightCnt && heightCnt >= timeCnt)
            return height;
        if (time !== DEFAULT_LOCKTIME)
            return time;
        return this.global.fallbackLocktime || DEFAULT_LOCKTIME;
    }
    get version() {
        // Should be not possible
        if (this.global.txVersion === undefined)
            throw new Error('No global.txVersion');
        return this.global.txVersion;
    }
    inputStatus(idx) {
        this.checkInputIdx(idx);
        const input = this.inputs[idx];
        // Finalized
        if (input.finalScriptSig && input.finalScriptSig.length)
            return 'finalized';
        if (input.finalScriptWitness && input.finalScriptWitness.length)
            return 'finalized';
        // Signed taproot
        if (input.tapKeySig)
            return 'signed';
        if (input.tapScriptSig && input.tapScriptSig.length)
            return 'signed';
        // Signed
        if (input.partialSig && input.partialSig.length)
            return 'signed';
        return 'unsigned';
    }
    // Cannot replace unpackSighash, tests rely on very generic implemenetation with signing inputs outside of range
    // We will lose some vectors -> smaller test coverage of preimages (very important!)
    inputSighash(idx) {
        this.checkInputIdx(idx);
        const sighash = this.inputType(this.inputs[idx]).sighash;
        // ALL or DEFAULT -- everything signed
        // NONE           -- all inputs + no outputs
        // SINGLE         -- all inputs + output with same index
        // ALL + ANYONE   -- specific input + all outputs
        // NONE + ANYONE  -- specific input + no outputs
        // SINGLE         -- specific inputs + output with same index
        const sigOutputs = sighash === SignatureHash.DEFAULT ? SignatureHash.ALL : sighash & 0b11;
        const sigInputs = sighash & SignatureHash.ANYONECANPAY;
        return { sigInputs, sigOutputs };
    }
    // Very nice for debug purposes, but slow. If there is too much inputs/outputs to add, will be quadratic.
    // Some cache will be nice, but there chance to have bugs with cache invalidation
    signStatus() {
        // if addInput or addOutput is not possible, then all inputs or outputs are signed
        let addInput = true, addOutput = true;
        let inputs = [], outputs = [];
        for (let idx = 0; idx < this.inputs.length; idx++) {
            const status = this.inputStatus(idx);
            // Unsigned input doesn't affect anything
            if (status === 'unsigned')
                continue;
            const { sigInputs, sigOutputs } = this.inputSighash(idx);
            // Input type
            if (sigInputs === SignatureHash.ANYONECANPAY)
                inputs.push(idx);
            else
                addInput = false;
            // Output type
            if (sigOutputs === SignatureHash.ALL)
                addOutput = false;
            else if (sigOutputs === SignatureHash.SINGLE)
                outputs.push(idx);
            else if (sigOutputs === SignatureHash.NONE) {
                // Doesn't affect any outputs at all
            }
            else
                throw new Error(`Wrong signature hash output type: ${sigOutputs}`);
        }
        return { addInput, addOutput, inputs, outputs };
    }
    get isFinal() {
        for (let idx = 0; idx < this.inputs.length; idx++)
            if (this.inputStatus(idx) !== 'finalized')
                return false;
        return true;
    }
    // Info utils
    get hasWitnesses() {
        let out = false;
        for (const i of this.inputs)
            if (i.finalScriptWitness && i.finalScriptWitness.length)
                out = true;
        return out;
    }
    // https://en.bitcoin.it/wiki/Weight_units
    get weight() {
        if (!this.isFinal)
            throw new Error('Transaction is not finalized');
        // TODO: Can we find out how much witnesses/script will be used before signing?
        let out = 32;
        const outputs = this.outputs.map(outputBeforeSign);
        if (this.hasWitnesses)
            out += 2;
        out += 4 * CompactSizeLen.encode(this.inputs.length).length;
        out += 4 * CompactSizeLen.encode(this.outputs.length).length;
        for (const i of this.inputs)
            if (i.finalScriptSig)
                out += 160 + 4 * VarBytes.encode(i.finalScriptSig).length;
        for (const o of outputs)
            out += 32 + 4 * VarBytes.encode(o.script).length;
        if (this.hasWitnesses) {
            for (const i of this.inputs)
                if (i.finalScriptWitness)
                    out += RawWitness.encode(i.finalScriptWitness).length;
        }
        return out;
    }
    get vsize() {
        return Math.ceil(this.weight / 4);
    }
    toBytes(withScriptSig = false, withWitness = false) {
        return RawTx.encode({
            version: this.version,
            lockTime: this.lockTime,
            inputs: this.inputs.map(inputBeforeSign).map((i) => ({
                ...i,
                finalScriptSig: (withScriptSig && i.finalScriptSig) || P.EMPTY,
            })),
            outputs: this.outputs.map(outputBeforeSign),
            witnesses: this.inputs.map((i) => i.finalScriptWitness || []),
            segwitFlag: withWitness && this.hasWitnesses,
        });
    }
    get unsignedTx() {
        return this.toBytes(false, false);
    }
    get hex() {
        return hex.encode(this.toBytes(true, this.hasWitnesses));
    }
    get hash() {
        if (!this.isFinal)
            throw new Error('Transaction is not finalized');
        return hex.encode(sha256x2(this.toBytes(true)));
    }
    get id() {
        if (!this.isFinal)
            throw new Error('Transaction is not finalized');
        return hex.encode(sha256x2(this.toBytes(true)).reverse());
    }
    // Input stuff
    checkInputIdx(idx) {
        if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.inputs.length)
            throw new Error(`Wrong input index=${idx}`);
    }
    getInput(idx) {
        this.checkInputIdx(idx);
        return cloneDeep(this.inputs[idx]);
    }
    get inputsLength() {
        return this.inputs.length;
    }
    // Modification
    normalizeInput(i, cur, allowedFields) {
        let { nonWitnessUtxo, txid } = i;
        // String support for common fields. We usually prefer Uint8Array to avoid errors (like hex looking string accidentally passed),
        // however in case of nonWitnessUtxo it is better to expect string, since constructing this complex object will be difficult for user
        if (typeof nonWitnessUtxo === 'string')
            nonWitnessUtxo = hex.decode(nonWitnessUtxo);
        if (isBytes(nonWitnessUtxo))
            nonWitnessUtxo = RawTx.decode(nonWitnessUtxo);
        if (nonWitnessUtxo === undefined)
            nonWitnessUtxo = cur?.nonWitnessUtxo;
        if (typeof txid === 'string')
            txid = hex.decode(txid);
        if (txid === undefined)
            txid = cur?.txid;
        let res = { ...cur, ...i, nonWitnessUtxo, txid };
        if (res.nonWitnessUtxo === undefined)
            delete res.nonWitnessUtxo;
        if (res.sequence === undefined)
            res.sequence = DEFAULT_SEQUENCE;
        if (res.tapMerkleRoot === null)
            delete res.tapMerkleRoot;
        res = mergeKeyMap(PSBTInput, res, cur, allowedFields);
        PSBTInputCoder.encode(res); // Validates that everything is correct at this point
        let prevOut;
        if (res.nonWitnessUtxo && res.index !== undefined)
            prevOut = res.nonWitnessUtxo.outputs[res.index];
        else if (res.witnessUtxo)
            prevOut = res.witnessUtxo;
        if (prevOut && !this.opts.disableScriptCheck)
            checkScript(prevOut && prevOut.script, res.redeemScript, res.witnessScript);
        return res;
    }
    addInput(input, _ignoreSignStatus = false) {
        if (!_ignoreSignStatus && !this.signStatus().addInput)
            throw new Error('Tx has signed inputs, cannot add new one');
        this.inputs.push(this.normalizeInput(input));
        return this.inputs.length - 1;
    }
    updateInput(idx, input, _ignoreSignStatus = false) {
        this.checkInputIdx(idx);
        let allowedFields = undefined;
        if (!_ignoreSignStatus) {
            const status = this.signStatus();
            if (!status.addInput || status.inputs.includes(idx))
                allowedFields = PSBTInputUnsignedKeys;
        }
        this.inputs[idx] = this.normalizeInput(input, this.inputs[idx], allowedFields);
    }
    // Output stuff
    checkOutputIdx(idx) {
        if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.outputs.length)
            throw new Error(`Wrong output index=${idx}`);
    }
    getOutput(idx) {
        this.checkOutputIdx(idx);
        return cloneDeep(this.outputs[idx]);
    }
    get outputsLength() {
        return this.outputs.length;
    }
    normalizeOutput(o, cur, allowedFields) {
        let { amount, script } = o;
        if (amount === undefined)
            amount = cur?.amount;
        if (typeof amount !== 'bigint')
            throw new Error('amount must be bigint sats');
        if (typeof script === 'string')
            script = hex.decode(script);
        if (script === undefined)
            script = cur?.script;
        let res = { ...cur, ...o, amount, script };
        if (res.amount === undefined)
            delete res.amount;
        res = mergeKeyMap(PSBTOutput, res, cur, allowedFields);
        PSBTOutputCoder.encode(res);
        if (res.script &&
            !this.opts.allowUnknowOutput &&
            OutScript.decode(res.script).type === 'unknown') {
            throw new Error('Transaction/output: unknown output script type, there is a chance that input is unspendable. Pass allowUnkownScript=true, if you sure');
        }
        if (!this.opts.disableScriptCheck)
            checkScript(res.script, res.redeemScript, res.witnessScript);
        return res;
    }
    addOutput(o, _ignoreSignStatus = false) {
        if (!_ignoreSignStatus && !this.signStatus().addOutput)
            throw new Error('Tx has signed outputs, cannot add new one');
        this.outputs.push(this.normalizeOutput(o));
        return this.outputs.length - 1;
    }
    updateOutput(idx, output, _ignoreSignStatus = false) {
        this.checkOutputIdx(idx);
        let allowedFields = undefined;
        if (!_ignoreSignStatus) {
            const status = this.signStatus();
            if (!status.addOutput || status.outputs.includes(idx))
                allowedFields = PSBTOutputUnsignedKeys;
        }
        this.outputs[idx] = this.normalizeOutput(output, this.outputs[idx], allowedFields);
    }
    addOutputAddress(address, amount, network = NETWORK) {
        return this.addOutput({ script: OutScript.encode(Address(network).decode(address)), amount });
    }
    // Utils
    get fee() {
        let res = 0n;
        for (const i of this.inputs) {
            const prevOut = this.prevOut(i);
            if (!prevOut)
                throw new Error('Empty input amount');
            res += prevOut.amount;
        }
        const outputs = this.outputs.map(outputBeforeSign);
        for (const o of outputs)
            res -= o.amount;
        return res;
    }
    // Signing
    // Based on https://github.com/bitcoin/bitcoin/blob/5871b5b5ab57a0caf9b7514eb162c491c83281d5/test/functional/test_framework/script.py#L624
    // There is optimization opportunity to re-use hashes for multiple inputs for witness v0/v1,
    // but we are trying to be less complicated for audit purpose for now.
    preimageLegacy(idx, prevOutScript, hashType) {
        const { isAny, isNone, isSingle } = unpackSighash(hashType);
        if (idx < 0 || !Number.isSafeInteger(idx))
            throw new Error(`Invalid input idx=${idx}`);
        if ((isSingle && idx >= this.outputs.length) || idx >= this.inputs.length)
            return P.U256BE.encode(1n);
        prevOutScript = Script.encode(Script.decode(prevOutScript).filter((i) => i !== 'CODESEPARATOR'));
        let inputs = this.inputs
            .map(inputBeforeSign)
            .map((input, inputIdx) => ({
            ...input,
            finalScriptSig: inputIdx === idx ? prevOutScript : P.EMPTY,
        }));
        if (isAny)
            inputs = [inputs[idx]];
        else if (isNone || isSingle) {
            inputs = inputs.map((input, inputIdx) => ({
                ...input,
                sequence: inputIdx === idx ? input.sequence : 0,
            }));
        }
        let outputs = this.outputs.map(outputBeforeSign);
        if (isNone)
            outputs = [];
        else if (isSingle) {
            outputs = outputs.slice(0, idx).fill(EMPTY_OUTPUT).concat([outputs[idx]]);
        }
        const tmpTx = RawTx.encode({
            lockTime: this.lockTime,
            version: this.version,
            segwitFlag: false,
            inputs,
            outputs,
        });
        return sha256x2(tmpTx, P.I32LE.encode(hashType));
    }
    preimageWitnessV0(idx, prevOutScript, hashType, amount) {
        const { isAny, isNone, isSingle } = unpackSighash(hashType);
        let inputHash = EMPTY32;
        let sequenceHash = EMPTY32;
        let outputHash = EMPTY32;
        const inputs = this.inputs.map(inputBeforeSign);
        const outputs = this.outputs.map(outputBeforeSign);
        if (!isAny)
            inputHash = sha256x2(...inputs.map(TxHashIdx.encode));
        if (!isAny && !isSingle && !isNone)
            sequenceHash = sha256x2(...inputs.map((i) => P.U32LE.encode(i.sequence)));
        if (!isSingle && !isNone) {
            outputHash = sha256x2(...outputs.map(RawOutput.encode));
        }
        else if (isSingle && idx < outputs.length)
            outputHash = sha256x2(RawOutput.encode(outputs[idx]));
        const input = inputs[idx];
        return sha256x2(P.I32LE.encode(this.version), inputHash, sequenceHash, P.bytes(32, true).encode(input.txid), P.U32LE.encode(input.index), VarBytes.encode(prevOutScript), P.U64LE.encode(amount), P.U32LE.encode(input.sequence), outputHash, P.U32LE.encode(this.lockTime), P.U32LE.encode(hashType));
    }
    preimageWitnessV1(idx, prevOutScript, hashType, amount, codeSeparator = -1, leafScript, leafVer = 0xc0, annex) {
        if (!Array.isArray(amount) || this.inputs.length !== amount.length)
            throw new Error(`Invalid amounts array=${amount}`);
        if (!Array.isArray(prevOutScript) || this.inputs.length !== prevOutScript.length)
            throw new Error(`Invalid prevOutScript array=${prevOutScript}`);
        const out = [
            P.U8.encode(0),
            P.U8.encode(hashType),
            P.I32LE.encode(this.version),
            P.U32LE.encode(this.lockTime),
        ];
        const outType = hashType === SignatureHash.DEFAULT ? SignatureHash.ALL : hashType & 0b11;
        const inType = hashType & SignatureHash.ANYONECANPAY;
        const inputs = this.inputs.map(inputBeforeSign);
        const outputs = this.outputs.map(outputBeforeSign);
        if (inType !== SignatureHash.ANYONECANPAY) {
            out.push(...[
                inputs.map(TxHashIdx.encode),
                amount.map(P.U64LE.encode),
                prevOutScript.map(VarBytes.encode),
                inputs.map((i) => P.U32LE.encode(i.sequence)),
            ].map((i) => sha256(concat(...i))));
        }
        if (outType === SignatureHash.ALL) {
            out.push(sha256(concat(...outputs.map(RawOutput.encode))));
        }
        const spendType = (annex ? 1 : 0) | (leafScript ? 2 : 0);
        out.push(new Uint8Array([spendType]));
        if (inType === SignatureHash.ANYONECANPAY) {
            const inp = inputs[idx];
            out.push(TxHashIdx.encode(inp), P.U64LE.encode(amount[idx]), VarBytes.encode(prevOutScript[idx]), P.U32LE.encode(inp.sequence));
        }
        else
            out.push(P.U32LE.encode(idx));
        if (spendType & 1)
            out.push(sha256(VarBytes.encode(annex || P.EMPTY)));
        if (outType === SignatureHash.SINGLE)
            out.push(idx < outputs.length ? sha256(RawOutput.encode(outputs[idx])) : EMPTY32);
        if (leafScript)
            out.push(tapLeafHash(leafScript, leafVer), P.U8.encode(0), P.I32LE.encode(codeSeparator));
        return schnorr.utils.taggedHash('TapSighash', ...out);
    }
    // Utils for sign/finalize
    // Used pretty often, should be fast
    prevOut(input) {
        if (input.nonWitnessUtxo) {
            if (input.index === undefined)
                throw new Error('Uknown input index');
            return input.nonWitnessUtxo.outputs[input.index];
        }
        else if (input.witnessUtxo)
            return input.witnessUtxo;
        else
            throw new Error('Cannot find previous output info.');
    }
    inputType(input) {
        let txType = 'legacy';
        let defaultSighash = SignatureHash.ALL;
        const prevOut = this.prevOut(input);
        const first = OutScript.decode(prevOut.script);
        let type = first.type;
        let cur = first;
        const stack = [first];
        if (first.type === 'tr') {
            defaultSighash = SignatureHash.DEFAULT;
            return {
                txType: 'taproot',
                type: 'tr',
                last: first,
                lastScript: prevOut.script,
                defaultSighash,
                sighash: input.sighashType || defaultSighash,
            };
        }
        else {
            if (first.type === 'wpkh' || first.type === 'wsh')
                txType = 'segwit';
            if (first.type === 'sh') {
                if (!input.redeemScript)
                    throw new Error('inputType: sh without redeemScript');
                let child = OutScript.decode(input.redeemScript);
                if (child.type === 'wpkh' || child.type === 'wsh')
                    txType = 'segwit';
                stack.push(child);
                cur = child;
                type += `-${child.type}`;
            }
            // wsh can be inside sh
            if (cur.type === 'wsh') {
                if (!input.witnessScript)
                    throw new Error('inputType: wsh without witnessScript');
                let child = OutScript.decode(input.witnessScript);
                if (child.type === 'wsh')
                    txType = 'segwit';
                stack.push(child);
                cur = child;
                type += `-${child.type}`;
            }
            const last = stack[stack.length - 1];
            if (last.type === 'sh' || last.type === 'wsh')
                throw new Error('inputType: sh/wsh cannot be terminal type');
            const lastScript = OutScript.encode(last);
            const res = {
                type,
                txType,
                last,
                lastScript,
                defaultSighash,
                sighash: input.sighashType || defaultSighash,
            };
            if (txType === 'legacy' && !this.opts.allowLegacyWitnessUtxo && !input.nonWitnessUtxo) {
                throw new Error(`Transaction/sign: legacy input without nonWitnessUtxo, can result in attack that forces paying higher fees. Pass allowLegacyWitnessUtxo=true, if you sure`);
            }
            return res;
        }
    }
    // Signer can be privateKey OR instance of bip32 HD stuff
    signIdx(privateKey, idx, allowedSighash, _auxRand) {
        this.checkInputIdx(idx);
        const input = this.inputs[idx];
        const inputType = this.inputType(input);
        // Handle BIP32 HDKey
        if (!isBytes(privateKey)) {
            if (!input.bip32Derivation || !input.bip32Derivation.length)
                throw new Error('bip32Derivation: empty');
            const signers = input.bip32Derivation
                .filter((i) => i[1].fingerprint == privateKey.fingerprint)
                .map(([pubKey, { path }]) => {
                let s = privateKey;
                for (const i of path)
                    s = s.deriveChild(i);
                if (!P.equalBytes(s.publicKey, pubKey))
                    throw new Error('bip32Derivation: wrong pubKey');
                if (!s.privateKey)
                    throw new Error('bip32Derivation: no privateKey');
                return s;
            });
            if (!signers.length)
                throw new Error(`bip32Derivation: no items with fingerprint=${privateKey.fingerprint}`);
            let signed = false;
            for (const s of signers)
                if (this.signIdx(s.privateKey, idx))
                    signed = true;
            return signed;
        }
        // Sighash checks
        // Just for compat with bitcoinjs-lib, so users won't face unexpected behaviour.
        if (!allowedSighash)
            allowedSighash = [inputType.defaultSighash];
        const sighash = inputType.sighash;
        if (!allowedSighash.includes(sighash)) {
            throw new Error(`Input with not allowed sigHash=${sighash}. Allowed: ${allowedSighash.join(', ')}`);
        }
        // It is possible to sign these inputs for legacy/segwit v0 (but no taproot!),
        // however this was because of bug in bitcoin-core, which remains here because of consensus.
        // If this is absolutely neccessary for your case, please open issue.
        // We disable it to avoid complicated workflow where SINGLE will block adding new outputs
        const { sigInputs, sigOutputs } = this.inputSighash(idx);
        if (sigOutputs === SignatureHash.SINGLE && idx >= this.outputs.length) {
            throw new Error(`Input with sighash SINGLE, but there is no output with corresponding index=${idx}`);
        }
        // Actual signing
        // Taproot
        const prevOut = this.prevOut(input);
        if (inputType.txType === 'taproot') {
            if (input.tapBip32Derivation)
                throw new Error('tapBip32Derivation unsupported');
            const prevOuts = this.inputs.map(this.prevOut);
            const prevOutScript = prevOuts.map((i) => i.script);
            const amount = prevOuts.map((i) => i.amount);
            let signed = false;
            let schnorrPub = schnorr.getPublicKey(privateKey);
            let merkleRoot = input.tapMerkleRoot || P.EMPTY;
            if (input.tapInternalKey) {
                // internal + tweak = tweaked key
                // if internal key == current public key, we need to tweak private key,
                // otherwise sign as is. bitcoinjs implementation always wants tweaked
                // priv key to be provided
                const { pubKey, privKey } = getTaprootKeys(privateKey, schnorrPub, input.tapInternalKey, merkleRoot);
                const [taprootPubKey, parity] = taprootTweakPubkey(input.tapInternalKey, merkleRoot);
                if (P.equalBytes(taprootPubKey, pubKey)) {
                    const hash = this.preimageWitnessV1(idx, prevOutScript, sighash, amount);
                    const sig = concat(schnorr.sign(hash, privKey, _auxRand), sighash !== SignatureHash.DEFAULT ? new Uint8Array([sighash]) : P.EMPTY);
                    this.updateInput(idx, { tapKeySig: sig }, true);
                    signed = true;
                }
            }
            if (input.tapLeafScript) {
                input.tapScriptSig = input.tapScriptSig || [];
                for (const [cb, _script] of input.tapLeafScript) {
                    const script = _script.subarray(0, -1);
                    const scriptDecoded = Script.decode(script);
                    const ver = _script[_script.length - 1];
                    const hash = tapLeafHash(script, ver);
                    const { pubKey, privKey } = getTaprootKeys(privateKey, schnorrPub, cb.internalKey, P.EMPTY // Because we cannot have nested taproot tree
                    );
                    const pos = scriptDecoded.findIndex((i) => isBytes(i) && P.equalBytes(i, pubKey));
                    // Skip if there is no public key in tapLeafScript
                    if (pos === -1)
                        continue;
                    const msg = this.preimageWitnessV1(idx, prevOutScript, sighash, amount, undefined, script, ver);
                    const sig = concat(schnorr.sign(msg, privKey, _auxRand), sighash !== SignatureHash.DEFAULT ? new Uint8Array([sighash]) : P.EMPTY);
                    this.updateInput(idx, { tapScriptSig: [[{ pubKey: pubKey, leafHash: hash }, sig]] }, true);
                    signed = true;
                }
            }
            if (!signed)
                throw new Error('No taproot scripts signed');
            return true;
        }
        else {
            // only compressed keys are supported for now
            const pubKey = _pubECDSA(privateKey);
            // TODO: replace with explicit checks
            // Check if script has public key or its has inside
            let hasPubkey = false;
            const pubKeyHash = hash160(pubKey);
            for (const i of Script.decode(inputType.lastScript)) {
                if (isBytes(i) && (P.equalBytes(i, pubKey) || P.equalBytes(i, pubKeyHash)))
                    hasPubkey = true;
            }
            if (!hasPubkey)
                throw new Error(`Input script doesn't have pubKey: ${inputType.lastScript}`);
            let hash;
            if (inputType.txType === 'legacy') {
                hash = this.preimageLegacy(idx, inputType.lastScript, sighash);
            }
            else if (inputType.txType === 'segwit') {
                let script = inputType.lastScript;
                // If wpkh OR sh-wpkh, wsh-wpkh is impossible, so looks ok
                if (inputType.last.type === 'wpkh')
                    script = OutScript.encode({ type: 'pkh', hash: inputType.last.hash });
                hash = this.preimageWitnessV0(idx, script, sighash, prevOut.amount);
            }
            else
                throw new Error(`Transaction/sign: unknown tx type: ${inputType.txType}`);
            const sig = signECDSA(hash, privateKey, this.opts.lowR);
            this.updateInput(idx, {
                partialSig: [[pubKey, concat(sig, new Uint8Array([sighash]))]],
            }, true);
        }
        return true;
    }
    // This is bad API. Will work if user creates and signs tx, but if
    // there is some complex workflow with exchanging PSBT and signing them,
    // then it is better to validate which output user signs. How could a better API look like?
    // Example: user adds input, sends to another party, then signs received input (mixer etc),
    // another user can add different input for same key and user will sign it.
    // Even worse: another user can add bip32 derivation, and spend money from different address.
    // Better api: signIdx
    sign(privateKey, allowedSighash, _auxRand) {
        let num = 0;
        for (let i = 0; i < this.inputs.length; i++) {
            try {
                if (this.signIdx(privateKey, i, allowedSighash, _auxRand))
                    num++;
            }
            catch (e) { }
        }
        if (!num)
            throw new Error('No inputs signed');
        return num;
    }
    finalizeIdx(idx) {
        this.checkInputIdx(idx);
        if (this.fee < 0n)
            throw new Error('Outputs spends more than inputs amount');
        const input = this.inputs[idx];
        const inputType = this.inputType(input);
        // Taproot finalize
        if (inputType.txType === 'taproot') {
            if (input.tapKeySig)
                input.finalScriptWitness = [input.tapKeySig];
            else if (input.tapLeafScript && input.tapScriptSig) {
                // Sort leafs by control block length.
                const leafs = input.tapLeafScript.sort((a, b) => TaprootControlBlock.encode(a[0]).length - TaprootControlBlock.encode(b[0]).length);
                for (const [cb, _script] of leafs) {
                    // Last byte is version
                    const script = _script.slice(0, -1);
                    const ver = _script[_script.length - 1];
                    const outScript = OutScript.decode(script);
                    const hash = tapLeafHash(script, ver);
                    const scriptSig = input.tapScriptSig.filter((i) => P.equalBytes(i[0].leafHash, hash));
                    let signatures = [];
                    if (outScript.type === 'tr_ms') {
                        const m = outScript.m;
                        const pubkeys = outScript.pubkeys;
                        let added = 0;
                        for (const pub of pubkeys) {
                            const sigIdx = scriptSig.findIndex((i) => P.equalBytes(i[0].pubKey, pub));
                            // Should have exact amount of signatures (more -- will fail)
                            if (added === m || sigIdx === -1) {
                                signatures.push(P.EMPTY);
                                continue;
                            }
                            signatures.push(scriptSig[sigIdx][1]);
                            added++;
                        }
                        // Should be exact same as m
                        if (added !== m)
                            continue;
                    }
                    else if (outScript.type === 'tr_ns') {
                        for (const pub of outScript.pubkeys) {
                            const sigIdx = scriptSig.findIndex((i) => P.equalBytes(i[0].pubKey, pub));
                            if (sigIdx === -1)
                                continue;
                            signatures.push(scriptSig[sigIdx][1]);
                        }
                        if (signatures.length !== outScript.pubkeys.length)
                            continue;
                    }
                    else if (outScript.type === 'unknown' && this.opts.allowUnknowInput) {
                        // Trying our best to sign what we can
                        const scriptDecoded = Script.decode(script);
                        signatures = scriptSig
                            .map(([{ pubKey }, signature]) => {
                            const pos = scriptDecoded.findIndex((i) => isBytes(i) && P.equalBytes(i, pubKey));
                            if (pos === -1)
                                throw new Error('finalize/taproot: cannot find position of pubkey in script');
                            return { signature, pos };
                        })
                            // Reverse order (because witness is stack and we take last element first from it)
                            .sort((a, b) => a.pos - b.pos)
                            .map((i) => i.signature);
                        if (!signatures.length)
                            continue;
                    }
                    else
                        throw new Error('Finalize: Unknown tapLeafScript');
                    // Witness is stack, so last element will be used first
                    input.finalScriptWitness = signatures
                        .reverse()
                        .concat([script, TaprootControlBlock.encode(cb)]);
                    break;
                }
                if (!input.finalScriptWitness)
                    throw new Error('finalize/taproot: empty witness');
            }
            else
                throw new Error('finalize/taproot: unknown input');
            input.finalScriptSig = P.EMPTY;
            cleanFinalInput(input);
            return;
        }
        if (!input.partialSig || !input.partialSig.length)
            throw new Error('Not enough partial sign');
        let inputScript = P.EMPTY;
        let witness = [];
        // TODO: move input scripts closer to payments/output scripts
        // Multisig
        if (inputType.last.type === 'ms') {
            const m = inputType.last.m;
            const pubkeys = inputType.last.pubkeys;
            let signatures = [];
            // partial: [pubkey, sign]
            for (const pub of pubkeys) {
                const sign = input.partialSig.find((s) => P.equalBytes(pub, s[0]));
                if (!sign)
                    continue;
                signatures.push(sign[1]);
            }
            signatures = signatures.slice(0, m);
            if (signatures.length !== m) {
                throw new Error(`Multisig: wrong signatures count, m=${m} n=${pubkeys.length} signatures=${signatures.length}`);
            }
            inputScript = Script.encode([0, ...signatures]);
        }
        else if (inputType.last.type === 'pk') {
            inputScript = Script.encode([input.partialSig[0][1]]);
        }
        else if (inputType.last.type === 'pkh') {
            inputScript = Script.encode([input.partialSig[0][1], input.partialSig[0][0]]);
        }
        else if (inputType.last.type === 'wpkh') {
            inputScript = P.EMPTY;
            witness = [input.partialSig[0][1], input.partialSig[0][0]];
        }
        else if (inputType.last.type === 'unknown' && !this.opts.allowUnknowInput)
            throw new Error('Unknown inputs not allowed');
        // Create final scripts (generic part)
        let finalScriptSig, finalScriptWitness;
        if (inputType.type.includes('wsh-')) {
            // P2WSH
            if (inputScript.length && inputType.lastScript.length) {
                witness = Script.decode(inputScript).map((i) => {
                    if (i === 0)
                        return P.EMPTY;
                    if (isBytes(i))
                        return i;
                    throw new Error(`Wrong witness op=${i}`);
                });
            }
            witness = witness.concat(inputType.lastScript);
        }
        if (inputType.txType === 'segwit')
            finalScriptWitness = witness;
        if (inputType.type.startsWith('sh-wsh-')) {
            finalScriptSig = Script.encode([Script.encode([0, sha256(inputType.lastScript)])]);
        }
        else if (inputType.type.startsWith('sh-')) {
            finalScriptSig = Script.encode([...Script.decode(inputScript), inputType.lastScript]);
        }
        else if (inputType.type.startsWith('wsh-')) {
        }
        else if (inputType.txType !== 'segwit')
            finalScriptSig = inputScript;
        if (!finalScriptSig && !finalScriptWitness)
            throw new Error('Unknown error finalizing input');
        if (finalScriptSig)
            input.finalScriptSig = finalScriptSig;
        if (finalScriptWitness)
            input.finalScriptWitness = finalScriptWitness;
        cleanFinalInput(input);
    }
    finalize() {
        for (let i = 0; i < this.inputs.length; i++)
            this.finalizeIdx(i);
    }
    extract() {
        if (!this.isFinal)
            throw new Error('Transaction has unfinalized inputs');
        if (!this.outputs.length)
            throw new Error('Transaction has no outputs');
        if (this.fee < 0n)
            throw new Error('Outputs spends more than inputs amount');
        return this.toBytes(true, true);
    }
    combine(other) {
        for (const k of ['PSBTVersion', 'version', 'lockTime']) {
            if (this.opts[k] !== other.opts[k]) {
                throw new Error(`Transaction/combine: different ${k} this=${this.opts[k]} other=${other.opts[k]}`);
            }
        }
        for (const k of ['inputs', 'outputs']) {
            if (this[k].length !== other[k].length) {
                throw new Error(`Transaction/combine: different ${k} length this=${this[k].length} other=${other[k].length}`);
            }
        }
        const thisUnsigned = this.global.unsignedTx ? RawTx.encode(this.global.unsignedTx) : P.EMPTY;
        const otherUnsigned = other.global.unsignedTx ? RawTx.encode(other.global.unsignedTx) : P.EMPTY;
        if (!P.equalBytes(thisUnsigned, otherUnsigned))
            throw new Error(`Transaction/combine: different unsigned tx`);
        this.global = mergeKeyMap(PSBTGlobal, this.global, other.global);
        for (let i = 0; i < this.inputs.length; i++)
            this.updateInput(i, other.inputs[i], true);
        for (let i = 0; i < this.outputs.length; i++)
            this.updateOutput(i, other.outputs[i], true);
        return this;
    }
    clone() {
        // deepClone probably faster, but this enforces that encoding is valid
        return Transaction.fromPSBT(this.toPSBT(2), this.opts);
    }
}
// User facing API?
// Simple pubkey address, without complex scripts
export function getAddress(type, privKey, network = NETWORK) {
    if (type === 'tr') {
        return p2tr(schnorr.getPublicKey(privKey), undefined, network).address;
    }
    const pubKey = _pubECDSA(privKey);
    if (type === 'pkh')
        return p2pkh(pubKey, network).address;
    if (type === 'wpkh')
        return p2wpkh(pubKey, network).address;
    throw new Error(`getAddress: unknown type=${type}`);
}
export function multisig(m, pubkeys, sorted = false, witness = false) {
    const ms = p2ms(m, sorted ? _sortPubkeys(pubkeys) : pubkeys);
    return witness ? p2wsh(ms) : p2sh(ms);
}
export function sortedMultisig(m, pubkeys, witness = false) {
    return multisig(m, pubkeys, true, witness);
}
// Copy-pasted from bip32 derive, maybe do something like 'bip32.parsePath'?
const HARDENED_OFFSET = 0x80000000;
export function bip32Path(path) {
    const out = [];
    if (!/^[mM]'?/.test(path))
        throw new Error('Path must start with "m" or "M"');
    if (/^[mM]'?$/.test(path))
        return out;
    const parts = path.replace(/^[mM]'?\//, '').split('/');
    for (const c of parts) {
        const m = /^(\d+)('?)$/.exec(c);
        if (!m || m.length !== 3)
            throw new Error(`Invalid child index: ${c}`);
        let idx = +m[1];
        if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET)
            throw new Error('Invalid index');
        // hardened key
        if (m[2] === "'")
            idx += HARDENED_OFFSET;
        out.push(idx);
    }
    return out;
}
export function PSBTCombine(psbts) {
    if (!psbts || !Array.isArray(psbts) || !psbts.length)
        throw new Error('PSBTCombine: wrong PSBT list');
    const tx = Transaction.fromPSBT(psbts[0]);
    for (let i = 1; i < psbts.length; i++)
        tx.combine(Transaction.fromPSBT(psbts[i]));
    return tx.toPSBT();
}
//# sourceMappingURL=index.js.map