'use strict';
/* eslint no-case-declarations: 0 */
/* eslint no-use-before-define: 0 */

const assert = require('assert');
const Output = require('./output');
const TX = require('./tx');
const bio = require('bufio');
const {BufferMap} = require('buffer-map');
const MTX = require('./mtx');
const Script = require('../script/script');
const Witness = require('../script/witness');
const {SignatureData} = require('../script/signaturedata');
const hash160 = require('bcrypto/lib/hash160');
const {encoding} = bio;
/*
 * Type Identifiers
 */

// global key
const PSBT_GLOBAL_UNSIGNED_TX = 0x00;

// input key
const PSBT_IN_NON_WITNESS_UTXO = 0x00;
const PSBT_IN_WITNESS_UTXO = 0x01;
const PSBT_IN_PARTIAL_SIG = 0x02;
const PSBT_IN_SIGHASH_TYPE = 0x03;
const PSBT_IN_REDEEM_SCRIPT = 0x04;
const PSBT_IN_WITNESS_SCRIPT = 0x05;
const PSBT_IN_BIP32_DERIVATION = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
// output key
const PSBT_OUT_REDEEM_SCRIPT = 0x00;
const PSBT_OUT_WITNESS_SCRIPT = 0x01;
const PSBT_OUT_BIP32_DERIVATION = 0x02;
// others
const MAGIC_BYTES = 0x70736274;
const GLOBAL_SEPARATOR = 0xff;

/**
 * PSBT
 * Partially Signed Bitcoin Transaction.
 * Common format to pass TX around between wallets.
 * Specified in BIP174
 * refs: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
 * @alias module:primitives.PSBT
 * @property {TX} tx
 * @property {PSBTInput[]} inputs
 * @property {PSBTOutput[]} outputs
 * @property {BufferMap} unknown - Unknown key-value pair
 */
class PSBT {
  constructor(options) {
    this.mtx = new MTX();
    this.inputs = [];
    this.outputs = [];
    // pubkey => HD Path object
    this.keyPaths = new BufferMap();
    this.unknown = new BufferMap();

    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    assert(options, 'PSBT Data is required');
    assert(TX.isTX(options.tx), 'TX Data is required for PSBT');
    this.mtx = MTX.fromTX(options.tx);

    if (options.inputs) {
      assert(Array.isArray(options.inputs), 'inputs must be array');
      for (const input of options.inputs) {
        this.inputs.push(new PSBTInput(input));
      }
    }

    if (options.outputs) {
      assert(Array.isArray(options.outputs), 'inputs must be array');
      for (const output of options.outputs) {
        this.outputs.push(new PSBTOutput(output));
      }
    }
    if (options.unknown) {
      assert(
        options.unknown instanceof BufferMap,
        'Unknown map must be BufferMap'
        );
      for (const [k, v] of options.unknown) {
        this.unknown.set(k, v);
      }
    }

    return this;
  }

  clone() {
    return new this.constructor().inject(this);
  }

  inject(psbt) {
    this.mtx = psbt.mtx.clone();
    for (const input of psbt.inputs) {
      this.inputs.push(input.clone());
    }

    for (const output of psbt.outputs) {
      this.outputs.push(output.clone());
    }
    return this;
  }

  /**
   * Serialize the PSBT.
   * @returns {Buffer} Serialized PSBT.
   */

  toJSON() {
    return this.getJSON();
  }

  getJSON() {
    const map = {};
    for (const [k, v] of this.unknown) {
      map[k.toString('hex')] = v.toString('hex');
    }
    return {
      mtx: this.mtx.toJSON(),
      inputs: this.inputs.map(i => i.toJSON()),
      outputs: this.outputs.map(o => o.toJSON()),
      unknown: map,
      fee: this.getFee()
    };
  }

  fromJSON(json) {}

  /**
   * returns user friendly representation.
   */

  inspect() {
    return this.format();
  }

  format() {
    return {
      tx: this.mtx.format(),
      inputs: this.inputs.map(i => i.format()),
      outputs: this.outputs.map(o => o.format())
    };
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  getSize() {
    let base = 0;
    base += 4; // magic bytes
    base += 1; // separator (0xff)
    base += encoding.sizeVarlen(1); // global key
    // tx must be in old serialization format regardless of if it has
    // witness or not. So we are using `etNormalSizes()` instead of get sizes
    base += encoding.sizeVarlen(this.mtx.getNormalSizes().size);
    base += 1; // separator
    base += this.inputs.reduce((a, b) => a + b.getSize(), 0);
    base += this.outputs.reduce((a, b) => a + b.getSize(), 0);

    return base;
  }

  /**
   * Write the PSBT record to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeU32BE(MAGIC_BYTES);
    bw.writeU8(GLOBAL_SEPARATOR);
    this.globalsToWriter(bw);

    bw.writeU8(0x00); // sep

    for (const psbtin of this.inputs) {
      psbtin.toWriter(bw);
    }

    for (const psbtout of this.outputs) {
      psbtout.toWriter(bw);
    }

    return bw;
  }

  globalsToWriter(bw) {
    bw.writeVarint(1); // key length
    bw.writeU8(PSBT_GLOBAL_UNSIGNED_TX); // actual key
    bw.writeVarBytes(this.mtx.toNormal()); // must be non-witness serialization.
  }

  // --------------- methods for reading

  /**
   * @param {Buffer} data - raw data.
   * @param {String} enc - "base64" or "hex"
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  fromReader(br) {
    br.start();
    const magic = br.readU32BE();
    const sep = br.readU8();
    if (magic !== MAGIC_BYTES || sep !== GLOBAL_SEPARATOR)
      throw new Error('Bad magic bytes');

    this.mtx = MTX.fromTX(this.globalsFromReader(br));
    for (const i in this.mtx.inputs) {
      this.inputs[i] = PSBTInput.fromReader(br);
    }

    for (const i in this.mtx.outputs) {
      this.outputs[i] = PSBTOutput.fromReader(br);
    }

    const checkResult = this.checkSanity();
    assert(checkResult[0], checkResult[1]);
    return this;
  }

  globalsFromReader(br) {
    let key = br.readVarBytes();
    assert(key.readUInt8() === PSBT_GLOBAL_UNSIGNED_TX, 'Bad key for global');

    const txBuffer = br.readVarBytes();
    const tx = TX.fromRaw(txBuffer);
    for (const i of tx.inputs) {
      assert(
        i.script.code.length <= 0 && i.witness.items.length <= 0,
        'Global tx for psbt can not have script by itself'
      );
    }

    // We know second key for global KVMap should actually be separator.
    // but asserting to make sure nothing went wrong.
    key = br.readVarBytes();
    assert(key.equals(Buffer.from('')));
    return tx;
  };

  /**
   * Get the transaction fee paid if all
   * UTXOs slots in the psbt have been filled.
   * @returns {Number} - fee.
   */
  getFee() {
    return this.mtx.getFee();
  }

  isSane() {
    const [valid] = this.checkSanity();
    return valid;
  }

  checkSanity() {
    const prevouts = this.mtx.inputs.map(i => i.prevout);
    for (const i in this.inputs) {
      const input = this.inputs[i];
      if (!input.isSane()) {
        return [false, 'bad-psbtin-malformed', 100];
      }
      // if PSBT Input has txid info, check if it matches to the one of tx.
      if (!input.nonWitnessUTXO.isNull()) {
        if (prevouts.every(p => !(p.hash.equals(input.nonWitnessUTXO.hash())))) {
          return [false, 'bad-psbtin-txid-mismatch', 100];
        }
      }
    }
    return [true, 'valid', 0];
  }

  /**
   * Sign witohut checking
   * @param {KeyRing} ring
   * @param {hashType} type
   * @param {Number} index - txin index to sign.
   */

  sign(ring, type, index) {
    const input = this.inputs[index];
    if (!input.nonWitnessUTXO.isNull()) {
      this.signNonWitness(ring, type, input);
    } else if (input.witnessUTXO.script.code.length > 0) {
      this.signWitness();
    }
  }

  signNonWitness(ring, type, psbtin, index) {
    // TODO: this validation shuold be done when decoding.
    if (psbtin.nonWitnessUTXO.hash !== this.mtx.inputs[index].prevout.hash) {
      throw new ParseError(
        'malformed',
        'txid in prevout does not match'
        );
    }
  }

  signWitness() {}

  /**
   * Sign with checking if the input is in the coinview.
   * Add witness, redeemScript.
   * @param {Number} index
   * @param {KeyRing} ring
   * @param {hashType} type
   */

  update(index, ring, type) {
    for (const psbtin of this.inputs) {
      assert(this.view.has(psbtin.hash),
        'Could not find previous out in coinview');
    }

    this.sign(ring, type);
  };

  addCoin(coin) {
    this.mtx.addCoin(coin);
    const input = PSBTInput.fromCoin(coin);
    this.inputs.push(input);
  }

  addOutput(script, value) {
    this.mtx.addOutput(script, value);
    let output;
    if (value !== null)
      output = PSBTOutput.fromScript(script, value);
    else
      output = PSBTOutput.fromOptions(script);
    this.outputs.push(output);

    return output;
  };

  /**
   * Combine with another PSBT
   * @param {PSBT} psbt - another psbt to combine.
   * @returns {PSBT}
   */

  merge(psbt) {
    // check if psbt is not the same
    // eslint-disable-next-line max-len
    assert(this.hasSameTX(psbt), 'psbt can be combined only with a tx which references same inputs and outputs');
    for (const i in psbt) {
      this.inputs[i].merge(psbt[i]);
    }
    for (const i in psbt) {
      this.outputs[i].merge(psbt[i]);
    }
    for (const [k, v] of psbt.unknown) {
      this.unknown.set(k, v);
    }
  }

  hasSameTX(psbt) {
    return this.mtx.hash === psbt.mtx.hash;
  }

  finalize() {
    this.mtx.check(this.view, this.flags);
  };

  static isPSBT(obj) {
    return obj instanceof PSBT;
  }
}

// Holder for an input KVMap
class PSBTInput {
  /**
   * @param {Options} options
   * @property {TX} nonWitnessUTXO - previous TX from which this input spends.
   *   This is required for HW Wallet to know the exact amount for the tx
   *   they are signing for.
   * @property {Output} witnessUTXO - for sighash v1, HW Wallet can verify
   *   the output amount directly. So there are no need to include whole tx,
   *   thus using Output
   * @property {Script} redeem - redeem script
   * @property {Witness} witness - witness script. Note that this is not an
   *   whole witness, but only witnessScript.
   * @property {BufferMap} keyInfo - public Key Buffer -> KeyOriginInfo map
   * @property {BufferMap} signatures - public Key Buffer -> Signature map
   * @property {BufferMap} unknown - key-value pair of unknown info.
   * @property {Script} scriptWitness - finalized scriptWitness
   * @property {Witness} finalScriptSig - finalized scriptSig
   */

  constructor(options) {
    this.nonWitnessUTXO = new TX();
    this.witnessUTXO = new Output();
    this.sighash = -1;
    this.redeem = new Script();
    this.witness = new Script();
    this.finalScriptSig = null;
    this.finalScriptWitness = null;
    this.signatures = new BufferMap();
    this.keyInfo = new BufferMap();
    this.unknown = new BufferMap();
    if (options) {
      this.fromOptions(options);
    }
  }

  get complete() {
    return this.finalScriptSig || this.finalScriptWitness;
  }

  fromOptions(options) {
    if (options.finalScriptSig) {
      assert(typeof options.finalScriptSig === 'object');
      this.finalScriptSig = Script.fromOptions(options.finalScriptSig);
    }
    if (options.finalScriptWitness) {
      assert(typeof options.finalScriptWitness === 'object');
      this.finalScriptWitness = Witness.fromOptions(options.finalScriptWitness);
    }
    if (options.nonWitnessUTXO) {
      this.nonWitnessUTXO = TX.fromOptions(options.nonWitnessUTXO);
    }
    if (options.witnessUTXO) {
      this.witnessUTXO = Output.fromOptions(options.witnessUTXO);
    }
    if (options.sighash) {
      assert(options.sighash >>> 0 === options.sighash);
      this.sighash = options.sighash;
    }
    if (options.redeem) {
      assert(typeof options.redeem === 'object');
      this.redeem = Script.fromOptions(options.redeem);
    }
    if (options.witness) {
      assert(typeof options.witness === 'object');
      this.witness = Witness.fromOptions(options.witness);
    }
    if (options.signatures) {
      for (const [k, v] of options.signatures) {
        assert(Buffer.isBuffer(k) && Buffer.isBuffer(v));
        this.signatures.set(k, v);
      }
    }
    if (options.keyInfo) {
      for (const [k, v] of options.keyInfo) {
        assert(Buffer.isBuffer(k) && Buffer.isBuffer(v));
        this.keyInfo.set(k, v);
      }
    }
    if (options.unknown) {
      for (const [k, v] of options.unknown) {
        assert(Buffer.isBuffer(k) && Buffer.isBuffer(v));
        this.unknown.set(k, v);
      }
    }

    return this;
  }

  static fromOptions(options) {
    return new PSBTInput().fromOptions(options);
  }

  clone() {
    const psbtin = new this.constructor();
    psbtin.nonWitnessUTXO = this.nonWitnessUTXO.clone();
    psbtin.witnessUTXO = this.witnessUTXO.clone();
    psbtin.witness = this.witness.clone();
    psbtin.redeem = this.redeem.clone();
    psbtin.sighash = this.sighash;
    psbtin.signatures = new BufferMap();
    for (const [k, v] of this.signatures) {
      psbtin.signatures.set(Buffer.from(k), Buffer.from(v));
    }
    for (const [k, v] of this.keyInfo) {
      psbtin.keyInfo.set(Buffer.from(k), Buffer.from(v));
    }
    for (const [k, v] of this.unknown) {
      psbtin.unknown.set(Buffer.from(k), Buffer.from(v));
    }
    if (this.finalScriptSig) {
      psbtin.finalScriptSig = this.finalScriptSig.clone();
    }
    if (this.finalScriptWitness) {
      psbtin.finalScriptWitness = this.finalScriptWitness.clone();
    }
    return psbtin;
  };

  clear() {
    this.nonWitnessUTXO = new TX();
    this.witnessUTXO = new Output();
    this.redeem.clear();
    this.witness.clear();
    this.sighash = -1;
    this.signatures.clear();
    this.keyInfo.clear();
    this.unknown.clear();
    this.finalScriptSig = null;
    this.finalScriptWitness = null;
  }

  getSize() {
    let base = 0;
    if (!this.nonWitnessUTXO.isNull()) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.nonWitnessUTXO.getSize()); // value
    }

    if (this.witnessUTXO.script.code.length > 0) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.witnessUTXO.getSize()); // value
    }

    if (this.redeem.code.length > 0) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.redeem.getSize());
    }

    if (this.witness.code.length > 0) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.witness.getSize());
    }

    if (this.sighash)  {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(4);
    }

    if (this.finalScriptSig) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.finalScriptSig.getSize());
    }

    if (this.finalScriptWitness) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.finalScriptWitness.getSize());
    }

    for (const [k, v] of this.signatures) {
      base += encoding.sizeVarlen(1 + k.length);
      base += encoding.sizeVarlen(v.length);
    }

    for (const [k, v] of this.keyInfo) {
      base += encoding.sizeVarlen(1 + k.length);
      base += encoding.sizeVarlen(v.length);
    }

    for (const [k, v] of this.unknown) {
      base += encoding.sizeVarlen(k.length);
      base += encoding.sizeVarlen(v.length);
    }

    base += 1; // sep
    return base;
  }

  fromSignatureData(sig) {
    assert(SignatureData.isSignatureData(sig), 'must pass SignatureData');
    if (sig.complete) {
      this.clear();
      if (sig.script) {
        this.finalScriptSig = sig.script;
      } else if (sig.witness) {
        this.finalScriptWitness = sig.witness;
      } else {
        throw Error('malformed SignatureData');
      }
      return;
    }
  }

  static fromSignatureData(sig) {
    return new PSBTInput().fromSignatureData(sig);
  }

  fillSignatureData(sigdata) {
    assert(SignatureData.isSignatureData(sigdata), 'must pass SignatureData');
    if (this.finalScriptSig) {
      sigdata.script = Buffer.from(this.finalScriptSig);
      sigdata.complete = true;
    }
    if (this.finalScriptWitness) {
      sigdata.witness = Buffer.from(this.finalScriptWitness);
      sigdata.complete = true;
    }
    if (sigdata.complete)
      return;

    for (const [pk, sig] of this.signatures) {
      sigdata.signatures.set(hash160(pk), Buffer.from(sig));
    }
    if (this.redeem.code.length > 0) {
      sigdata.script = this.redeem.clone();
    }
    if (this.witness.items.length > 0) {
      sigdata.witness = this.witness.clone();
    }
    for (const [k, info] of this.keyInfo) {
      sigdata.keyInfo.set(hash160(k), Buffer.from(info));
    }
  }

  merge(psbtIn) {
    assert(
      psbtIn instanceof PSBTInput,
      'PSBTInput can only be merged with PSBTInput'
    );
    assert(
      psbtIn.sighash === this.sighash,
      'cannot merge psbt input with different sighash'
    );
    if(this.nonWitnessUTXO.isNull() && !psbtIn.nonWitnessUTXO.isNull()) {
      this.nonWitnessUTXO = psbtIn.this.nonWitnessUTXO;
    }
    if (this.redeem.code.length === 0 && psbtIn.redeem) {
      this.redeem = psbtIn.redeem;
    }
    if (!this.witness.code.length === 0 && psbtIn.witness) {
      this.witness = psbtIn.witness;
    }

    if (!this.finalScriptSig && psbtIn.finalScriptSig) {
      this.finalScriptSig = psbtIn.finalScriptSig;
    }
    if (!this.finalScriptWitness && psbtIn.finalScriptWitness) {
      this.finalScriptWitness = psbtIn.finalScriptWitness;
    }
    if(this.WitnessUTXO.script.code.length === 0 &&
      psbtIn.witnessUTXO.script.code.length > 0) {
      this.witnessUTXO = psbtIn.witnessUTXO;
      // Clear out any non-witness utxo when we set a witness one.
      this.nonWitnessUTXO.clear();
    }

    for (const [k, v] of psbtIn.signatures) {
      this.signatures.set(k, v);
    }

    for (const [k, v] of psbtIn.keyInfo) {
      this.keyInfo.set(k, v);
    }

    for (const [k, v] of psbtIn.unknown) {
      this.unknown.set(k, v);
    }
  }

  isSane() {
    const [valid] = this.checkSanity();
    return valid;
  }

  checkSanity() {
    if (this.witnessUTXO.script.code.length > 0 && !this.nonWitnessUTXO.isNull())
      return [false, 'bad-psbtin-two-prevouts', 100];
    if (this.witness.code.length > 0 && !this.witnessUTXO)
      return [false, 'bad-psbtin-witness-script-with-no-utxo', 100];
    if (this.finalScriptWitness && !this.witnessUTXO)
      return [false, 'bad-psbtin-witness-script-with-no-utxo', 100];
    return [true, 'valid', 0];
  }

  sign(mtx, index, ring) {
    if (this.complete)
      // don't bother if this is already finalized.
      return;
    const { prevout } = mtx.inputs[index];
    const coin = mtx.view.getOutput(prevout);
    const version = this.witness.code.length > 0 ? 1 : 0;
    const sig = mtx.signature(
      index,
      prevout.script,
      coin.value,
      ring.privateKey,
      this.sighash,
      version
    );
    this.signatures.set(ring.publicKey, sig);
  }

  toJSON() {
    return this.getJSON();
  }

  getJSON() {
    const signaturesMap = {};
    for (const [k, v] of this.signatures) {
      signaturesMap[k.toString('hex')] = v.toString('hex');
    }

    const keyInfoMap = {};
    for (const [k, v] of this.keyInfo) {
      keyInfoMap[k.toString('hex')] = v.toJSON();
    }

    const unknownMap = {};
    for (const [k, v] of this.unknown) {
      unknownMap[k.toString('hex')] = v.toString('hex');
    }

    return {
      nonWitnessUTXO: this.nonWitnessUTXO.toJSON(),
      witnessUTXO: this.witnessUTXO.toJSON(),
      sighash: this.sighash,
      redeem: this.redeem.toJSON(),
      witness: this.witness.toJSON(),
      finalScriptSig: this.finalScriptSig ? this.finalScriptSig.toJSON() : '',
      finalScriptWitness: this.finalScriptWitness ?
        this.finalScriptWitness.toJSON() :
        '',
      signatures: signaturesMap,
      keyInfo: keyInfoMap,
      unknown: unknownMap
    };
  }

  inspect() {
    return this.format();
  }

  format() {
    return {
      nonWitnessUTXO: this.nonWitnessUTXO.format(),
      witnessUTXO: this.witnessUTXO.toString(),
      sighash: this.sighash,
      redeem: this.redeem.toString(),
      witness: this.witness.toString(),
      finalScriptSig: this.finalScriptSig ? this.finalScriptSig.toString() : '',
      finalScriptWitness: this.finalScriptWitness ?
        this.finalScriptWitness.toString() : ''
    }
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  toWriter(bw) {
    if (!this.nonWitnessUTXO.isNull()) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_NON_WITNESS_UTXO);
      bw.writeVarBytes(this.nonWitnessUTXO.toRaw());
    }

    if (this.witnessUTXO.script.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_WITNESS_UTXO);
      bw.writeVarBytes(this.witnessUTXO.toRaw());
    }

    if (this.redeem.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_REDEEM_SCRIPT);
      bw.writeVarBytes(this.redeem.toRaw());
    }

    if (this.witness.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_WITNESS_SCRIPT);
      bw.writeVarBytes(this.witness.toRaw());
    }

    if (this.sighash) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_SIGHASH_TYPE);
      bw.writeVarint(4);
      bw.writeU32(this.sighash);
    }

    if (this.finalScriptSig) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_FINAL_SCRIPTSIG);
      bw.writeVarBytes(this.finalScriptSig.toRaw());
    }

    if (this.finalScriptWitness) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_FINAL_SCRIPTWITNESS);
      bw.writeVarBytes(this.finalScriptWitness.toRaw());
    }

    for (const [k, v] of this.signatures) {
      bw.writeVarBytes(Buffer.concat([Buffer.from([PSBT_IN_PARTIAL_SIG]), k]));
      bw.writeVarBytes(v);
    }

    for (const [k, v] of this.keyInfo) {
      bw.writeVarBytes(
          Buffer.concat([Buffer.from([PSBT_IN_BIP32_DERIVATION]), k])
        );
      bw.writeVarBytes(v);
    }

    for (const [k, v] of this.unknown) {
      bw.writeVarBytes(k);
      bw.writeVarBytes(v);
    }
    bw.writeU8(0x00); // sep

    return bw;
  }

  static fromRaw(data) {
    return new this().fromRaw();
  }

  fromRaw(data) {
    assert(Buffer.isBuffer(data), 'must pass buffer');
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  fromReader(br) {
    br.start();
    let key = br.readVarBytes();
    let value;
    let pubkey;
    while (!key.equals(Buffer.from(''))) {
      value = br.readVarBytes();
      switch(key.readUInt8()) {
        case PSBT_IN_NON_WITNESS_UTXO:
          assert(this.nonWitnessUTXO.isNull(), 'duplicate key for nonWitnessUTXO');
          assert(key.length === 1, 'key for nonWitnessUTXO should be 1 byte');
          this.nonWitnessUTXO = TX.fromRaw(value);
          break;
        case PSBT_IN_WITNESS_UTXO:
          assert(
             this.witnessUTXO.script.code.length === 0,
            'duplicate key for witnessUTXO'
            );
          assert(key.length === 1, 'key for witnessUTXO should be 1 byte');
          this.witnessUTXO = Output.fromRaw(value);
          break;
        case PSBT_IN_PARTIAL_SIG:
          pubkey = key.slice(1);
          assert(!this.signatures.has(pubkey), 'duplicate key for witnessUTXO');
          assert(
            pubkey.length === 33 || pubkey.length === 65, // compressed or not.
            'public key size for partial sig is not correct.'
          );
          this.signatures.set(pubkey, value);
          break;
        case PSBT_IN_SIGHASH_TYPE:
          assert(this.sighash === -1, 'duplicate key for sighash');
          assert(key.length === 1, 'key for sighash should be 1 byte');
          this.sighash = value.readUInt8();
          break;
        case PSBT_IN_REDEEM_SCRIPT:
          assert(this.redeem.code.length === 0, 'duplicate key for redeem script.');
          assert(key.length === 1, 'key for redeem script should be 1 byte');
          this.redeem = Script.fromRaw(value);
          break;
        case PSBT_IN_WITNESS_SCRIPT:
          assert(this.witness.code.length === 0, 'duplicate key for witness script.');
          assert(key.length === 1, 'key for witness script should be 1 byte');
          this.witness = Script.fromRaw(value);
          break;
        case PSBT_IN_BIP32_DERIVATION:
          // TODO: needs assertion?
          pubkey = key.slice(1);
          this.keyInfo.set(pubkey, value);
          break;
        case PSBT_IN_FINAL_SCRIPTSIG:
          assert(!this.finalScriptSig, 'duplicate key for scriptSig.');
          assert(key.length === 1, 'key for scriptSig should be 1 byte');
          this.finalScriptSig = Script.fromRaw(value);
          break;
        case PSBT_IN_FINAL_SCRIPTWITNESS:
          assert(!this.finalScriptSig, 'duplicate key for scriptWitness.');
          assert(key.length === 1, 'key for scriptWitness should be 1 byte');
          this.finalScriptWitness = Witness.fromRaw(value);
          break;
        default:
          assert(!this.unknown.has(key), 'Duplicate key for output unknown map.');
          this.unknown.set(key, value);
      }
      key = br.readVarBytes();
    }
    br.end();
    return this;
  }

  static isPSBTInput(obj) {
    return obj instanceof PSBTInput;
  }
}

// Holder for an output KVMap
class PSBTOutput extends Output {
  constructor(options) {
    super();
    this.redeem = new Script();
    this.witness = new Script();
    this.keyInfo = new BufferMap();
    this.unknown = new BufferMap();
    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    if (options.redeem) {
      assert(typeof options.redeem === 'object');
      this.redeem = Script.fromOptions(options.redeem);
    }
    if (options.witness) {
      assert(typeof options.witness === 'object');
      this.redeem = Script.fromOptions(options.witness);
    }
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromScript(script, value) {}

  fromScript (script, value) {}

  merge(psbtOut) {}

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  toWriter(bw) {
    if (this.redeem.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_OUT_REDEEM_SCRIPT);
      bw.writeVarBytes(this.redeem.toRaw());
    }

    if (this.witness.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_OUT_WITNESS_SCRIPT);
      bw.writeVarBytes(this.witness.toRaw());
    }

    for (const [k, v] of this.keyInfo) {
      bw.writeVarBytes(
          Buffer.concat([Buffer.from([PSBT_OUT_BIP32_DERIVATION]), k])
        );
      bw.writeVarBytes(v);
    }

    for (const [k, v] of this.unknown) {
      bw.writeVarBytes(k);
      bw.writeVarBytes(v);
    }

    bw.writeU8(0x00); // sep
    return bw;
  }

  toJSON() {
    return this.getJSON();
  }

  getSize() {
    let base = 0;
    if (this.redeem.code.length > 0) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.redeem.getSize()); // value
    }
    if (this.witness.code.length > 0) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.witness.getSize()); // value
    }
    for (const [k, v] of this.keyInfo) {
      base += encoding.sizeVarlen(1 + k.length);
      base += encoding.sizeVarlen(v.length);
    }

    for (const [k, v] of this.unknown) {
      base += encoding.sizeVarlen(k.length);
      base += encoding.sizeVarlen(v.length);
    }

    base += 1;
    return base;
  }

  getJSON() {
    const keyInfoMap = {};
    for (const [k, v] of this.keyInfo) {
      keyInfoMap[k.toString('hex')] = v.toJSON();
    }

    const unknownMap = {};
    for (const [k, v] of this.unknown) {
      unknownMap[k.toString('hex')] = v.toString('hex');
    }
    return {
      redeem: this.redeem.toJSON(),
      witness: this.witness.toJSON(),
      keyInfo: keyInfoMap,
      unknown: unknownMap
    };
  }

  inspect() {
    return this.format();
  }

  format() {
    return {
      redeem: this.redeem.format(),
      witness: this.witness.format(),
      keyInfo: this.keyInfo,
      unknown: this.unknown
    };
  }

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw();
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  fromReader(br) {
    br.start();
    let key = br.readVarBytes();
    let value;
    let pubkey;
    while(!key.equals(Buffer.from(''))) {
      value = br.readVarBytes();
      switch(key.readUInt8()) {
        case PSBT_OUT_REDEEM_SCRIPT:
          assert(
              this.redeem.code.length === 0,
              'duplicate key for output redeem script.'
            );
          assert(key.length === 1, 'key for redeem script should be 1 byte');
          this.redeem = Script.fromRaw(value);
          break;
        case PSBT_OUT_WITNESS_SCRIPT:
          assert(
              !this.witness.items.length === 0,
              'duplicate key for output witness script.'
            );
          assert(key.length === 1, 'key for witness script should be 1 byte');
          this.witness = Script.fromRaw(value);
          break;
        case PSBT_OUT_BIP32_DERIVATION:
          pubkey = key.slice(1);
          this.keyInfo.set(pubkey, value);
          break;
        default:
          assert(!this.unknown.has(key), 'Duplicate key for output unknown map.');
          this.unknown.set(key, value);
          break;
      }
      key = br.readVarBytes();
    }
    br.end();
    return this;
  }
}

class ParseError extends Error {
  /**
   * create Parse Error
   * @param {String} code - read, malformed
   * @param {String} reason
   * @param {String?} rawdata - raw data failed to handle. `hex` or null
   * @param {Number?} position - positoin failed to decode
   */

  constructor(code, reason, rawdata, position) {
    super();
    assert(typeof code === 'string');
    assert(typeof reason === 'string');

    this.type = 'ParseError';
    this.code = code;
    this.reason = reason;

    console.log('position is');
    console.log(position);
    this.message = `Parse failure (code=${code} reason=${reason}) \n` +
      `${rawdata} \n` +
      ' '.repeat(position) + '^\n';

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, ParseError);
  }
}

module.exports = PSBT;
