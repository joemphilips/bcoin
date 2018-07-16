'use strict';

const BufferMap = require( 'buffer-map');
const Script = require('./script');
const Witness = require('./witness');
const Input = require('../primitives/input');
const assert = require('assert');
const consensus = require('../protocol/consensus');

/**
 * SignatureData
 * wrapper class for partial signatures and its metadata.
 * @alias module.primitives.SignatureData
 * @proerty {Boolean} complete - whether the scripgtSig and input.witness are
 * complete.
 * @perperty {Boolean} isWitness
 */
class SignatureData {
  constructor(options) {
    this.complete = false;
    this.script = null;
    this.witness = null;
    this.pubkeyMap = new BufferMap(); // pubkeyhash -> pubKey map
    this.signaturesMap = new BufferMap(); // pubkeyHash -> signature map.
    this.keyInfoMap = new BufferMap(); // pubkeyHash -> KeyOriginInfo
    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    assert(options, 'options required');

    if (options.script) {
      this.script = Script.fromOptions(options.script);
    }

    if (options.witness) {
      this.witness = Witness.fromOptions(options.witness);
    }
    if (options.script || options.witness) {
      this.complete = true;
    }

    if (options.signaturesMap) {
      for (const [k, v] of options.signaturesMap) {
        assert(
          k && Buffer.isBuffer(k),
          'Buffer for Public key hash is required.'
        );
        assert(
          v && Buffer.isBuffer(v),
          'signature buffer required.'
        );
        this.signaturesMap.set(k, v);
      }
    }

    if (options.pubkeyMap) {
      for (const [k, v] of options.pubkeyMap) {
        assert(
          k && Buffer.isBuffer(k),
          'Buffer for Public key hash is required.'
        );
        assert(
          v && Buffer.isBuffer(v),
          'pubkeyBuffer buffer required.'
        );
        this.pubkeyMap.set(k, v);
      }
    }

    if (options.this.keyInfoMap) {
      for (const [k, v] of options.pubkeyMap) {
        assert(
          k && Buffer.isBuffer(k),
          'Buffer for Public key hash is required.'
        );
        assert(
          v && v instanceof KeyOriginInfo,
          'KeyOriginInfo required.'
        );
        this.keyInfoMap.set(k, v);
      }
    }
    return this;
  }

  fromInput(input) {
    assert(Input.isInput(input), 'must pass input');
    if (input.witness) {
      this.witness = input.witness;
    }
  }

  static isSignatureData(obj) {
    return obj instanceof SignatureData;
  }
}

/**
 * Helper class to represent hd key path for arbitrary wallets.
 */
class KeyOriginInfo {
  constructor(options) {
    this.fingerPrint = consensus.ZERO_HASH;
    this.path = [];
    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    assert(options, 'requires options');
    if (options.fingerPrint) {
      assert(
        Buffer.isBuffer(options.fingerPrint),
        'fingerPrint must be Buffer'
      );
      this.fingerPrint = options.fingerPrint;
    }
    if (options.path) {
      assert(
        Array.isArray(options.path) &&
          options.path.forEach(p => Number.isNumber(p)),
        'path must be an array of numbers'
      );
      this.path = options.path;
    }
  }
}

module.exports.KeyOriginInfo = KeyOriginInfo;
module.exports.SignatureData = SignatureData;
