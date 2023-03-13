import type { Coder } from '@scure/base';
import * as P from 'micro-packed';
export declare type ExtendType<T, E> = {
    [K in keyof T]: K extends keyof E ? E[K] | T[K] : T[K];
};
export declare type RequireType<T, K extends keyof T> = T & {
    [P in K]-?: T[P];
};
export declare type Bytes = Uint8Array;
export declare const base58check: import("@scure/base").BytesCoder;
export declare function cloneDeep<T>(obj: T): T;
export declare function taprootTweakPrivKey(privKey: Uint8Array, merkleRoot?: Uint8Array): Uint8Array;
export declare function taprootTweakPubkey(pubKey: Uint8Array, h: Uint8Array): [Uint8Array, number];
export declare const NETWORK: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
};
export declare const TEST_NETWORK: typeof NETWORK;
export declare const PRECISION = 8;
export declare const DEFAULT_VERSION = 2;
export declare const DEFAULT_LOCKTIME = 0;
export declare const DEFAULT_SEQUENCE = 4294967295;
export declare const Decimal: {
    encode: (from: bigint) => string;
    decode: (to: string) => bigint;
};
export declare function _cmpBytes(a: Bytes, b: Bytes): number;
export declare enum OP {
    OP_0 = 0,
    PUSHDATA1 = 76,
    PUSHDATA2 = 77,
    PUSHDATA4 = 78,
    '1NEGATE' = 79,
    RESERVED = 80,
    OP_1 = 81,
    OP_2 = 82,
    OP_3 = 83,
    OP_4 = 84,
    OP_5 = 85,
    OP_6 = 86,
    OP_7 = 87,
    OP_8 = 88,
    OP_9 = 89,
    OP_10 = 90,
    OP_11 = 91,
    OP_12 = 92,
    OP_13 = 93,
    OP_14 = 94,
    OP_15 = 95,
    OP_16 = 96,
    NOP = 97,
    VER = 98,
    IF = 99,
    NOTIF = 100,
    VERIF = 101,
    VERNOTIF = 102,
    ELSE = 103,
    ENDIF = 104,
    VERIFY = 105,
    RETURN = 106,
    TOALTSTACK = 107,
    FROMALTSTACK = 108,
    '2DROP' = 109,
    '2DUP' = 110,
    '3DUP' = 111,
    '2OVER' = 112,
    '2ROT' = 113,
    '2SWAP' = 114,
    IFDUP = 115,
    DEPTH = 116,
    DROP = 117,
    DUP = 118,
    NIP = 119,
    OVER = 120,
    PICK = 121,
    ROLL = 122,
    ROT = 123,
    SWAP = 124,
    TUCK = 125,
    CAT = 126,
    SUBSTR = 127,
    LEFT = 128,
    RIGHT = 129,
    SIZE = 130,
    INVERT = 131,
    AND = 132,
    OR = 133,
    XOR = 134,
    EQUAL = 135,
    EQUALVERIFY = 136,
    RESERVED1 = 137,
    RESERVED2 = 138,
    '1ADD' = 139,
    '1SUB' = 140,
    '2MUL' = 141,
    '2DIV' = 142,
    NEGATE = 143,
    ABS = 144,
    NOT = 145,
    '0NOTEQUAL' = 146,
    ADD = 147,
    SUB = 148,
    MUL = 149,
    DIV = 150,
    MOD = 151,
    LSHIFT = 152,
    RSHIFT = 153,
    BOOLAND = 154,
    BOOLOR = 155,
    NUMEQUAL = 156,
    NUMEQUALVERIFY = 157,
    NUMNOTEQUAL = 158,
    LESSTHAN = 159,
    GREATERTHAN = 160,
    LESSTHANOREQUAL = 161,
    GREATERTHANOREQUAL = 162,
    MIN = 163,
    MAX = 164,
    WITHIN = 165,
    RIPEMD160 = 166,
    SHA1 = 167,
    SHA256 = 168,
    HASH160 = 169,
    HASH256 = 170,
    CODESEPARATOR = 171,
    CHECKSIG = 172,
    CHECKSIGVERIFY = 173,
    CHECKMULTISIG = 174,
    CHECKMULTISIGVERIFY = 175,
    NOP1 = 176,
    CHECKLOCKTIMEVERIFY = 177,
    CHECKSEQUENCEVERIFY = 178,
    NOP4 = 179,
    NOP5 = 180,
    NOP6 = 181,
    NOP7 = 182,
    NOP8 = 183,
    NOP9 = 184,
    NOP10 = 185,
    CHECKSIGADD = 186,
    INVALID = 255
}
declare type ScriptOP = keyof typeof OP | Bytes | number;
declare type ScriptType = ScriptOP[];
export declare const Script: P.CoderType<ScriptType>;
export declare function ScriptNum(bytesLimit?: number, forceMinimal?: boolean): P.CoderType<bigint>;
export declare function OpToNum(op: ScriptOP, bytesLimit?: number, forceMinimal?: boolean): number | undefined;
export declare const CompactSize: P.CoderType<bigint>;
export declare const BTCArray: <T>(t: P.CoderType<T>) => P.CoderType<T[]>;
export declare const VarBytes: P.CoderType<Uint8Array>;
export declare const RawInput: P.CoderType<{
    index: number;
    sequence: number;
    txid: Uint8Array;
    finalScriptSig: Uint8Array;
} & {}>;
export declare const RawOutput: P.CoderType<{
    script: Uint8Array;
    amount: bigint;
} & {}>;
export declare const RawWitness: P.CoderType<Uint8Array[]>;
export declare const RawTx: P.CoderType<{
    version: number;
    segwitFlag: boolean;
    inputs: ({
        index: number;
        sequence: number;
        txid: Uint8Array;
        finalScriptSig: Uint8Array;
    } & {})[];
    outputs: ({
        script: Uint8Array;
        amount: bigint;
    } & {})[];
    lockTime: number;
} & {
    witnesses?: P.Option<Uint8Array[][]>;
}>;
declare type PSBTKeyCoder = P.CoderType<any> | false;
declare type PSBTKeyMapInfo = Readonly<[
    number,
    PSBTKeyCoder,
    any,
    readonly number[],
    readonly number[],
    boolean
]>;
declare type PSBTKeyMap = Record<string, PSBTKeyMapInfo>;
export declare const TaprootControlBlock: P.CoderType<{
    version: number;
    internalKey: Uint8Array;
    merklePath: Uint8Array[];
} & {}>;
declare const PSBTUnknownKey: P.CoderType<{
    type: number;
    key: Uint8Array;
} & {}>;
declare type PSBTUnknownFields = {
    unknown?: [P.UnwrapCoder<typeof PSBTUnknownKey>, Bytes][];
};
declare type PSBTKeyMapKeys<T extends PSBTKeyMap> = {
    -readonly [K in keyof T]?: T[K][1] extends false ? P.UnwrapCoder<T[K][2]> : [P.UnwrapCoder<T[K][1]>, P.UnwrapCoder<T[K][2]>][];
} & PSBTUnknownFields;
declare function PSBTKeyMap<T extends PSBTKeyMap>(psbtEnum: T): P.CoderType<PSBTKeyMapKeys<T>>;
declare const PSBTInputCoder: P.CoderType<PSBTKeyMapKeys<{
    readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
        version: number;
        segwitFlag: boolean;
        inputs: ({
            index: number;
            sequence: number;
            txid: Uint8Array;
            finalScriptSig: Uint8Array;
        } & {})[];
        outputs: ({
            script: Uint8Array;
            amount: bigint;
        } & {})[];
        lockTime: number;
    } & {
        witnesses?: P.Option<Uint8Array[][]>;
    }>, readonly [], readonly [0, 2], false];
    readonly witnessUtxo: readonly [1, false, P.CoderType<{
        script: Uint8Array;
        amount: bigint;
    } & {}>, readonly [], readonly [0, 2], false];
    readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
    readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
        path: number[];
        fingerprint: number;
    } & {}>, readonly [], readonly [0, 2], false];
    readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
    readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
    readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
    readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
    readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
    readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
    readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly tapScriptSig: readonly [20, P.CoderType<{
        pubKey: Uint8Array;
        leafHash: Uint8Array;
    } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly tapLeafScript: readonly [21, P.CoderType<{
        version: number;
        internalKey: Uint8Array;
        merklePath: Uint8Array[];
    } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
        hashes: Uint8Array[];
        der: {
            path: number[];
            fingerprint: number;
        } & {};
    } & {}>, readonly [], readonly [0, 2], false];
    readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
}>>;
declare const PSBTOutputCoder: P.CoderType<PSBTKeyMapKeys<{
    readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
        path: number[];
        fingerprint: number;
    } & {}>, readonly [], readonly [0, 2], false];
    readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
    readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
    readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    readonly tapTree: readonly [6, false, P.CoderType<({
        script: Uint8Array;
        version: number;
        depth: number;
    } & {})[]>, readonly [], readonly [0, 2], false];
    readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
        hashes: Uint8Array[];
        der: {
            path: number[];
            fingerprint: number;
        } & {};
    } & {}>, readonly [], readonly [0, 2], false];
    readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
}>>;
export declare const _RawPSBTV0: P.CoderType<{
    global: PSBTKeyMapKeys<{
        readonly unsignedTx: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [0], readonly [0], false];
        readonly xpub: readonly [1, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly txVersion: readonly [2, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly fallbackLocktime: readonly [3, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly inputCount: readonly [4, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly outputCount: readonly [5, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly txModifiable: readonly [6, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly version: readonly [251, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    inputs: PSBTKeyMapKeys<{
        readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [], readonly [0, 2], false];
        readonly witnessUtxo: readonly [1, false, P.CoderType<{
            script: Uint8Array;
            amount: bigint;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
        readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
        readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
        readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapScriptSig: readonly [20, P.CoderType<{
            pubKey: Uint8Array;
            leafHash: Uint8Array;
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapLeafScript: readonly [21, P.CoderType<{
            version: number;
            internalKey: Uint8Array;
            merklePath: Uint8Array[];
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
    outputs: PSBTKeyMapKeys<{
        readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
        readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapTree: readonly [6, false, P.CoderType<({
            script: Uint8Array;
            version: number;
            depth: number;
        } & {})[]>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
} & {}>;
export declare const _RawPSBTV2: P.CoderType<{
    global: PSBTKeyMapKeys<{
        readonly unsignedTx: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [0], readonly [0], false];
        readonly xpub: readonly [1, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly txVersion: readonly [2, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly fallbackLocktime: readonly [3, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly inputCount: readonly [4, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly outputCount: readonly [5, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly txModifiable: readonly [6, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly version: readonly [251, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    inputs: PSBTKeyMapKeys<{
        readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [], readonly [0, 2], false];
        readonly witnessUtxo: readonly [1, false, P.CoderType<{
            script: Uint8Array;
            amount: bigint;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
        readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
        readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
        readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapScriptSig: readonly [20, P.CoderType<{
            pubKey: Uint8Array;
            leafHash: Uint8Array;
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapLeafScript: readonly [21, P.CoderType<{
            version: number;
            internalKey: Uint8Array;
            merklePath: Uint8Array[];
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
    outputs: PSBTKeyMapKeys<{
        readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
        readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapTree: readonly [6, false, P.CoderType<({
            script: Uint8Array;
            version: number;
            depth: number;
        } & {})[]>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
} & {}>;
export declare type PSBTRaw = typeof _RawPSBTV0 | typeof _RawPSBTV2;
export declare const _DebugPSBT: P.CoderType<{
    items: Record<string, string | Uint8Array>[];
} & {}>;
export declare const RawPSBTV0: P.CoderType<({
    global: PSBTKeyMapKeys<{
        readonly unsignedTx: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [0], readonly [0], false];
        readonly xpub: readonly [1, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly txVersion: readonly [2, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly fallbackLocktime: readonly [3, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly inputCount: readonly [4, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly outputCount: readonly [5, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly txModifiable: readonly [6, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly version: readonly [251, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    inputs: PSBTKeyMapKeys<{
        readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [], readonly [0, 2], false];
        readonly witnessUtxo: readonly [1, false, P.CoderType<{
            script: Uint8Array;
            amount: bigint;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
        readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
        readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
        readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapScriptSig: readonly [20, P.CoderType<{
            pubKey: Uint8Array;
            leafHash: Uint8Array;
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapLeafScript: readonly [21, P.CoderType<{
            version: number;
            internalKey: Uint8Array;
            merklePath: Uint8Array[];
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
    outputs: PSBTKeyMapKeys<{
        readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
        readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapTree: readonly [6, false, P.CoderType<({
            script: Uint8Array;
            version: number;
            depth: number;
        } & {})[]>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
} & {}) | ({
    global: PSBTKeyMapKeys<{
        readonly unsignedTx: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [0], readonly [0], false];
        readonly xpub: readonly [1, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly txVersion: readonly [2, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly fallbackLocktime: readonly [3, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly inputCount: readonly [4, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly outputCount: readonly [5, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly txModifiable: readonly [6, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly version: readonly [251, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    inputs: PSBTKeyMapKeys<{
        readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [], readonly [0, 2], false];
        readonly witnessUtxo: readonly [1, false, P.CoderType<{
            script: Uint8Array;
            amount: bigint;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
        readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
        readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
        readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapScriptSig: readonly [20, P.CoderType<{
            pubKey: Uint8Array;
            leafHash: Uint8Array;
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapLeafScript: readonly [21, P.CoderType<{
            version: number;
            internalKey: Uint8Array;
            merklePath: Uint8Array[];
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
    outputs: PSBTKeyMapKeys<{
        readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
        readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapTree: readonly [6, false, P.CoderType<({
            script: Uint8Array;
            version: number;
            depth: number;
        } & {})[]>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
} & {})>;
export declare const RawPSBTV2: P.CoderType<({
    global: PSBTKeyMapKeys<{
        readonly unsignedTx: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [0], readonly [0], false];
        readonly xpub: readonly [1, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly txVersion: readonly [2, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly fallbackLocktime: readonly [3, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly inputCount: readonly [4, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly outputCount: readonly [5, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly txModifiable: readonly [6, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly version: readonly [251, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    inputs: PSBTKeyMapKeys<{
        readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [], readonly [0, 2], false];
        readonly witnessUtxo: readonly [1, false, P.CoderType<{
            script: Uint8Array;
            amount: bigint;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
        readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
        readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
        readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapScriptSig: readonly [20, P.CoderType<{
            pubKey: Uint8Array;
            leafHash: Uint8Array;
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapLeafScript: readonly [21, P.CoderType<{
            version: number;
            internalKey: Uint8Array;
            merklePath: Uint8Array[];
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
    outputs: PSBTKeyMapKeys<{
        readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
        readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapTree: readonly [6, false, P.CoderType<({
            script: Uint8Array;
            version: number;
            depth: number;
        } & {})[]>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
} & {}) | ({
    global: PSBTKeyMapKeys<{
        readonly unsignedTx: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [0], readonly [0], false];
        readonly xpub: readonly [1, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly txVersion: readonly [2, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly fallbackLocktime: readonly [3, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly inputCount: readonly [4, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly outputCount: readonly [5, false, P.CoderType<number>, readonly [2], readonly [2], false];
        readonly txModifiable: readonly [6, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly version: readonly [251, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    inputs: PSBTKeyMapKeys<{
        readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [], readonly [0, 2], false];
        readonly witnessUtxo: readonly [1, false, P.CoderType<{
            script: Uint8Array;
            amount: bigint;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
        readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
        readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
        readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapScriptSig: readonly [20, P.CoderType<{
            pubKey: Uint8Array;
            leafHash: Uint8Array;
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapLeafScript: readonly [21, P.CoderType<{
            version: number;
            internalKey: Uint8Array;
            merklePath: Uint8Array[];
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
    outputs: PSBTKeyMapKeys<{
        readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
        readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapTree: readonly [6, false, P.CoderType<({
            script: Uint8Array;
            version: number;
            depth: number;
        } & {})[]>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>[];
} & {})>;
declare type P2Ret = {
    type: string;
    script: Bytes;
    address?: string;
    redeemScript?: Bytes;
    witnessScript?: Bytes;
};
declare type OutPKType = {
    type: 'pk';
    pubkey: Bytes;
};
export declare const p2pk: (pubkey: Bytes, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}) => P2Ret;
declare type OutPKHType = {
    type: 'pkh';
    hash: Bytes;
};
export declare const p2pkh: (publicKey: Bytes, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}) => P2Ret;
declare type OutSHType = {
    type: 'sh';
    hash: Bytes;
};
export declare const p2sh: (child: P2Ret, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}) => P2Ret;
declare type OutWSHType = {
    type: 'wsh';
    hash: Bytes;
};
export declare const p2wsh: (child: P2Ret, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}) => P2Ret;
declare type OutWPKHType = {
    type: 'wpkh';
    hash: Bytes;
};
export declare const p2wpkh: (publicKey: Bytes, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}) => P2Ret;
declare type OutMSType = {
    type: 'ms';
    pubkeys: Bytes[];
    m: number;
};
export declare const p2ms: (m: number, pubkeys: Bytes[], allowSamePubkeys?: boolean) => P2Ret;
declare type OutTRType = {
    type: 'tr';
    pubkey: Bytes;
};
export declare type TaprootNode = {
    script: Bytes | string;
    leafVersion?: number;
    weight?: number;
} & Partial<P2TROut>;
export declare type TaprootScriptTree = TaprootNode | TaprootScriptTree[];
export declare type TaprootScriptList = TaprootNode[];
export declare function taprootListToTree(taprootList: TaprootScriptList): TaprootScriptTree;
declare type TaprootLeaf = {
    type: 'leaf';
    version?: number;
    script: Bytes;
    hash: Bytes;
    path: Bytes[];
    tapInternalKey?: Bytes;
};
export declare const TAPROOT_UNSPENDABLE_KEY: Uint8Array;
export declare type P2TROut = P2Ret & {
    tweakedPubkey: Uint8Array;
    tapInternalKey: Uint8Array;
    tapMerkleRoot?: Uint8Array;
    tapLeafScript?: TransactionInput['tapLeafScript'];
    leaves?: TaprootLeaf[];
};
export declare function p2tr(internalPubKey?: Bytes | string, tree?: TaprootScriptTree, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}, allowUnknowOutput?: boolean): P2TROut;
declare type OutTRNSType = {
    type: 'tr_ns';
    pubkeys: Bytes[];
};
export declare function combinations<T>(m: number, list: T[]): T[][];
/**
 * M-of-N multi-leaf wallet via p2tr_ns. If m == n, single script is emitted.
 * Takes O(n^2) if m != n. 99-of-100 is ok, 5-of-100 is not.
 * `2-of-[A,B,C] => [A,B] | [A,C] | [B,C]`
 */
export declare const p2tr_ns: (m: number, pubkeys: Bytes[], allowSamePubkeys?: boolean) => P2Ret[];
export declare const p2tr_pk: (pubkey: Bytes) => P2Ret;
declare type OutTRMSType = {
    type: 'tr_ms';
    pubkeys: Bytes[];
    m: number;
};
export declare function p2tr_ms(m: number, pubkeys: Bytes[], allowSamePubkeys?: boolean): {
    type: string;
    script: Uint8Array;
};
declare type OutUnknownType = {
    type: 'unknown';
    script: Bytes;
};
export declare const OutScript: P.CoderType<OutWSHType | OutPKType | OutPKHType | OutSHType | OutWPKHType | OutMSType | OutTRType | OutTRNSType | OutTRMSType | OutUnknownType>;
export declare function programToWitness(version: number, data: Bytes, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}): string;
export declare function WIF(network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}): Coder<Bytes, string>;
export declare function Address(network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}): {
    encode(from: P.UnwrapCoder<typeof OutScript>): string;
    decode(address: string): P.UnwrapCoder<typeof OutScript>;
};
export declare enum SignatureHash {
    DEFAULT = 0,
    ALL = 1,
    NONE = 2,
    SINGLE = 3,
    ANYONECANPAY = 128
}
export declare const SigHashCoder: P.CoderType<"DEFAULT" | "ALL" | "NONE" | "SINGLE" | "ANYONECANPAY">;
export declare const _sortPubkeys: (pubkeys: Bytes[]) => Uint8Array[];
export declare type TransactionInput = P.UnwrapCoder<typeof PSBTInputCoder>;
export declare type TransactionInputUpdate = ExtendType<TransactionInput, {
    nonWitnessUtxo?: string | Bytes;
    txid?: string;
}>;
export declare type TransactionInputRequired = {
    txid: Bytes;
    index: number;
    sequence: number;
    finalScriptSig: Bytes;
};
export declare type TransactionOutput = P.UnwrapCoder<typeof PSBTOutputCoder>;
export declare type TransactionOutputUpdate = ExtendType<TransactionOutput, {
    script?: string;
}>;
export declare type TransactionOutputRequired = {
    script: Bytes;
    amount: bigint;
};
export declare const TAP_LEAF_VERSION = 192;
export declare const tapLeafHash: (script: Bytes, version?: number) => Uint8Array;
interface HDKey {
    publicKey: Bytes;
    privateKey: Bytes;
    fingerprint: number;
    derive(path: string): HDKey;
    deriveChild(index: number): HDKey;
    sign(hash: Bytes): Bytes;
}
export declare type Signer = Bytes | HDKey;
export declare type TxOpts = {
    version?: number;
    lockTime?: number;
    PSBTVersion?: number;
    allowUnknowOutput?: boolean;
    allowUnknowInput?: boolean;
    disableScriptCheck?: boolean;
    bip174jsCompat?: boolean;
    allowLegacyWitnessUtxo?: boolean;
    lowR?: boolean;
};
declare function validateOpts(opts: TxOpts): Readonly<{
    version: number;
    lockTime: number;
    PSBTVersion: number;
    allowUnknowOutput?: boolean | undefined;
    allowUnknowInput?: boolean | undefined;
    disableScriptCheck?: boolean | undefined;
    bip174jsCompat?: boolean | undefined;
    allowLegacyWitnessUtxo?: boolean | undefined;
    lowR?: boolean | undefined;
}>;
export declare class Transaction {
    private global;
    private inputs;
    private outputs;
    readonly opts: ReturnType<typeof validateOpts>;
    constructor(opts?: TxOpts);
    static fromRaw(raw: Bytes, opts?: TxOpts): Transaction;
    static fromPSBT(psbt: Bytes, opts?: TxOpts): Transaction;
    toPSBT(PSBTVersion?: number): Uint8Array;
    get lockTime(): number;
    get version(): number;
    private inputStatus;
    private inputSighash;
    private signStatus;
    get isFinal(): boolean;
    get hasWitnesses(): boolean;
    get weight(): number;
    get vsize(): number;
    toBytes(withScriptSig?: boolean, withWitness?: boolean): Uint8Array;
    get unsignedTx(): Bytes;
    get hex(): string;
    get hash(): string;
    get id(): string;
    private checkInputIdx;
    getInput(idx: number): PSBTKeyMapKeys<{
        readonly nonWitnessUtxo: readonly [0, false, P.CoderType<{
            version: number;
            segwitFlag: boolean;
            inputs: ({
                index: number;
                sequence: number;
                txid: Uint8Array;
                finalScriptSig: Uint8Array;
            } & {})[];
            outputs: ({
                script: Uint8Array;
                amount: bigint;
            } & {})[];
            lockTime: number;
        } & {
            witnesses?: P.Option<Uint8Array[][]>;
        }>, readonly [], readonly [0, 2], false];
        readonly witnessUtxo: readonly [1, false, P.CoderType<{
            script: Uint8Array;
            amount: bigint;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly partialSig: readonly [2, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sighashType: readonly [3, false, P.CoderType<number>, readonly [], readonly [0, 2], false];
        readonly redeemScript: readonly [4, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [6, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly finalScriptSig: readonly [7, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly finalScriptWitness: readonly [8, false, P.CoderType<Uint8Array[]>, readonly [], readonly [0, 2], false];
        readonly porCommitment: readonly [9, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly ripemd160: readonly [10, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly sha256: readonly [11, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash160: readonly [12, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly hash256: readonly [13, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly txid: readonly [14, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly index: readonly [15, false, P.CoderType<number>, readonly [2], readonly [2], true];
        readonly sequence: readonly [16, false, P.CoderType<number>, readonly [], readonly [2], true];
        readonly requiredTimeLocktime: readonly [17, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly requiredHeightLocktime: readonly [18, false, P.CoderType<number>, readonly [], readonly [2], false];
        readonly tapKeySig: readonly [19, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapScriptSig: readonly [20, P.CoderType<{
            pubKey: Uint8Array;
            leafHash: Uint8Array;
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapLeafScript: readonly [21, P.CoderType<{
            version: number;
            internalKey: Uint8Array;
            merklePath: Uint8Array[];
        } & {}>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [22, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly tapInternalKey: readonly [23, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapMerkleRoot: readonly [24, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    get inputsLength(): number;
    private normalizeInput;
    addInput(input: TransactionInputUpdate, _ignoreSignStatus?: boolean): number;
    updateInput(idx: number, input: TransactionInputUpdate, _ignoreSignStatus?: boolean): void;
    private checkOutputIdx;
    getOutput(idx: number): PSBTKeyMapKeys<{
        readonly redeemScript: readonly [0, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly witnessScript: readonly [1, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly bip32Derivation: readonly [2, P.CoderType<Uint8Array>, P.CoderType<{
            path: number[];
            fingerprint: number;
        } & {}>, readonly [], readonly [0, 2], false];
        readonly amount: readonly [3, false, P.CoderType<bigint>, readonly [2], readonly [2], true];
        readonly script: readonly [4, false, P.CoderType<Uint8Array>, readonly [2], readonly [2], true];
        readonly tapInternalKey: readonly [5, false, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
        readonly tapTree: readonly [6, false, P.CoderType<({
            script: Uint8Array;
            version: number;
            depth: number;
        } & {})[]>, readonly [], readonly [0, 2], false];
        readonly tapBip32Derivation: readonly [7, P.CoderType<Uint8Array>, P.CoderType<{
            hashes: Uint8Array[];
            der: {
                path: number[];
                fingerprint: number;
            } & {};
        } & {}>, readonly [], readonly [0, 2], false];
        readonly proprietary: readonly [252, P.CoderType<Uint8Array>, P.CoderType<Uint8Array>, readonly [], readonly [0, 2], false];
    }>;
    get outputsLength(): number;
    private normalizeOutput;
    addOutput(o: TransactionOutputUpdate, _ignoreSignStatus?: boolean): number;
    updateOutput(idx: number, output: TransactionOutputUpdate, _ignoreSignStatus?: boolean): void;
    addOutputAddress(address: string, amount: bigint, network?: {
        bech32: string;
        pubKeyHash: number;
        scriptHash: number;
        wif: number;
    }): number;
    get fee(): bigint;
    private preimageLegacy;
    private preimageWitnessV0;
    private preimageWitnessV1;
    private prevOut;
    private inputType;
    signIdx(privateKey: Signer, idx: number, allowedSighash?: SignatureHash[], _auxRand?: Bytes): boolean;
    sign(privateKey: Signer, allowedSighash?: number[], _auxRand?: Bytes): number;
    finalizeIdx(idx: number): void;
    finalize(): void;
    extract(): Uint8Array;
    combine(other: Transaction): this;
    clone(): Transaction;
}
export declare function getAddress(type: 'pkh' | 'wpkh' | 'tr', privKey: Bytes, network?: {
    bech32: string;
    pubKeyHash: number;
    scriptHash: number;
    wif: number;
}): string | undefined;
export declare function multisig(m: number, pubkeys: Bytes[], sorted?: boolean, witness?: boolean): P2Ret;
export declare function sortedMultisig(m: number, pubkeys: Bytes[], witness?: boolean): P2Ret;
export declare function bip32Path(path: string): number[];
export declare function PSBTCombine(psbts: Bytes[]): Bytes;
export {};
//# sourceMappingURL=index.d.ts.map