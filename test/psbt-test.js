/* eslint-env mocha */
'use strict';

const PSBT = require('../lib/primitives/psbt');
const KeyRing = require('../lib/primitives/keyring');
const Outpoint = require('../lib/primitives/outpoint');
const Coin = require('../lib/primitives/coin');
const CoinView = require('../lib/coins/coinview');
const Script = require('../lib/script/script');
const common = require('../lib/script/common');
const HDPrivateKey = require('../lib/hd/private');
const KeyOriginInfo = require('../lib/hd/keyorigin');
const Amount = require('../lib/btc/amount');
const MTX = require('../lib/primitives/mtx');
const TX = require('../lib/primitives/tx');

const data = require('./data/psbt.json');

const util = require('../lib/utils/util');
const hash160 = require('bcrypto/lib/hash160');
const assert = require('./util/assert');

const WalletDB = require('../lib/wallet/walletdb');
const WorkerPool = require('../lib/workers/workerpool');
const Chain = require('../lib/blockchain/chain');

const workers = new WorkerPool({ enabled: true });
const wdb = new WalletDB({ workers });
const chain = new Chain({
  memory: true,
  workers
});

function assertPSBTEqual(actual, expected) {
  assert.bufferEqual(
    actual.tx.hash(),
    expected.tx.hash(),
    'tx hash must be same'
  );
  assert.strictEqual(actual.inputs.length, expected.inputs.length);
  assert.strictEqual(actual.outputs.length, expected.outputs.length);

  for (const i in expected.inputs) {
    const e = expected.inputs[i];
    const a = actual.inputs[i];
    if (!e.nonWitnessUTXO.isNull()) {
      assert(!a.nonWitnessUTXO.isNull(), 'nonWitnessUTXO must be same');
      assert.bufferEqual(
        e.nonWitnessUTXO.hash(),
        a.nonWitnessUTXO.hash(),
        'nonWitnessUTXO must be same'
      );
    }

    assert(e.witnessUTXO.equals(a.witnessUTXO),'witnessUTXO must be same');
    assert(e.redeem.equals(a.redeem), 'redeem must be same');
    assert(e.witness.equals(a.witness), 'witness must be same');
    assert.strictEqual(e.sighash, a.sighash, 'sighash must be same');

    assert.bufferMapEqual(
      a.keyInfo,
      e.keyInfo,
      compareKeyInfo,
      'mismatch in KeyInfo'
    );
    assert.bufferMapEqual(a.signatures, e.signatures);
    assert.bufferMapEqual(a.unknown, e.unknown);

    if (e.finalScriptSig) {
      assert(
        e.finalScriptSig.equals(a.finalScriptSig),
      'finalScriptSig must be same'
      );
    }

    if (e.finalScriptWitness) {
      assert(
        e.finalScriptWitness.equals(a.finalScriptWitness),
      'finalScriptSig must be same'
      );
    }
  };

  for (const i in expected.output) {
    const e = expected.output[i];
    const a = actual.output[i];
    assert(e.redeem.equals(a.redeem), 'redeem must be same');
    assert(e.witness.equals(a.witness), 'witness must be same');
    assert.bufferMapEqual(a.keyInfo, e.keyInfo);
    assert.bufferMapEqual(a.unknown, e.unknown);
  };
}

function compareKeyInfo(a, b, message) {
  assert(a.equals(b), message);
}

function assertFinalized(psbt, tx, witness) {
  if (witness) {
    const actual = psbt.inputs[0].finalScriptWitness;
    const expected = tx.inputs[0].witness;
    for (const i in actual.items) {
      assert.bufferEqual(
        actual.items[i],
        expected.items[i],
      );
    }
  } else {
    const actual = psbt.inputs[0].finalScriptSig;
    const expected = tx.inputs[0].script;
    assert(actual.equals(expected))
  }
}

/**
 * returns tx with 1 input and 1 output.
 * @param {KeyRing} ring - key to sign input.
 * @param {String} type - type of input. e.g. "p2wsh", "p2sh-p2wpkh".
 */

function templateTX(ring, type, numSign, m, n) {
  ring.witness = type.endsWith('p2wpkh') || type.endsWith('p2wsh');
  ring.nested = type === 'p2sh-p2wsh' || type === 'p2sh-p2wpkh';
  n = n <= 1 ? 1 : n;
  m = m <= 1 ? 1 : m;
  const keys = [];
  for (let k = 0; k < n; k++) {
    if (k === 0) {
      keys.push(ring);
      continue;
    }
    keys.push(KeyRing.generate());
  }
  keys[0].script = type.endsWith('p2wsh') || type === 'p2sh' ?
    Script.fromMultisig(m, n, keys.map(k => k.publicKey)) :
    null;
  ring.script = keys[0].script;

  const fundValue = Amount.fromBTC('0.1').toValue();
  const cb = new MTX();
  cb.addInput({
    prevout: new Outpoint(),
    script: new Script()
  });
  cb.addOutput({
    address: ring.getAddress(),
    value: fundValue
  });
  const coin = Coin.fromTX(cb.toTX(), 0, -1);

  const mtx = new MTX({version: 1});
  mtx.addTX(cb, 0);
  mtx.scriptInput(0, coin, ring);
  const ringOutput = KeyRing.generate();
  const outValue = Amount.fromBTC('0.08').toValue();
  mtx.addOutput(ringOutput.getAddress(), outValue);

  if (numSign > 0) {
    for (let i = 0; i < numSign; i++) {
      mtx.signInput(0, coin, keys[i]);
    }
  }

  return [keys[0], ringOutput, mtx, cb, keys];
}

function commonAssertion(psbt) {
  for (const i of psbt.tx.inputs) {
    assert.strictEqual(
       i.script.code.length, 0,
      'psbt should not hold script in global transaction'
    );
    assert.strictEqual(
      i.witness.items.length, 0,
      'psbt should not hold witness in global transaction'
    );
  }
  assert(
    psbt.inputs.length === psbt.tx.inputs.length &&
    psbt.outputs.length === psbt.tx.outputs.length,
    'psbt should have same number of [in|out]puts with global tx'
  );
}

describe('Partially Signed Bitcoin Transaction', () => {
  for (const i in data.invalid) {
    const testcase = data.invalid[i];
    it(`should fail to decode invalid psbt ${i}`, () => {
      let err;
      let result;
      try {
        result = PSBT.fromRaw(testcase, 'base64');
      } catch (e) {
        err = e;
      }
      assert.typeOf(err, 'error', `result was ${result}`);
    });
  }

  for (const i in data.valid) {
    const testcase = data.valid[i];
    it(`should encode and decode psbt ${i} without changing property`, () => {
      const testcaseBuf = Buffer.from(testcase, 'base64');
      const psbt = PSBT.fromRaw(testcaseBuf);
      const raw = psbt.toRaw();
      const psbt2 = PSBT.fromRaw(raw);
      assertPSBTEqual(psbt2, psbt);
    });
  };

  for (const i in data.invalidForSigners) {
    const testcase = data.invalidForSigners[i];
    it(`should parse data but fails to sign for psbt ${i}`, () => {
      const psbt = PSBT.fromRaw(testcase, 'base64');
      const raw = psbt.toRaw();
      const psbt2 = PSBT.fromRaw(raw);
      assertPSBTEqual(psbt, psbt2);
      // TODO: assert it fails to check before signing.
    });
  }

  describe('Creator', () => {
    for (const sign of [true, false]) {
      const caseSigned = sign ? 'signed' : 'unsigned';
      it(`should instantiate from tx with ${caseSigned} p2wpkh input`, () => {
        const numSign = sign ? 1 : 0;
        const [, ringOut, mtx] = templateTX(KeyRing.generate(), 'p2wpkh', numSign, 1, 1);

        const [tx, view] = mtx.commit();
        const psbt = PSBT.fromTX(tx, view);

        commonAssertion(psbt);

        const wit = psbt.inputs[0].witness;
        assert(
          wit.equals(new Script()),
          'witness script in PSBTInput should be empty for p2wpkh input'
        );
        assert(
          ringOut.ownOutput(psbt.tx.outputs[0]),
          'psbt should preserve original tx output'
        );
        if (sign)
          assertFinalized(psbt, mtx, true);
    });
  };

  for (const numSign of [0, 1, 2]) {
    for (const type of ['p2wsh', 'p2sh-p2wsh']) {
      it(`can create from tx with ${numSign} signed ${type} input`, () => {
        const r = KeyRing.generate();
        const [ring, , mtx] = templateTX(r, type, numSign, 2, 2);

        const [tx, view] = mtx.commit();
        const psbt = PSBT.fromTX(tx, view);

        commonAssertion(psbt);
        const wit = psbt.inputs[0].witness;
        if (numSign === 0) {
          assert(
            wit.equals(ring.script),
            'witness script for p2wsh must be copied to PSBTInput'
          );
        }
        if (numSign === 1) {
          const witExpected = tx.inputs[0].witness;
          const [sigE] = witExpected.items
            .filter(i => common.isSignatureEncoding(i));
          const sig = psbt.inputs[0].signatures.get(ring.publicKey);
          assert.bufferEqual(sig, sigE, 'must preserve signature');
        }
        if (numSign === 2)
          assertFinalized(psbt, mtx, true);
      });
    }
  }
  });

  /*
  describe('Updater', () => {
    before(async () => {
      await chain.open();
    });
    after(async () => {
      await chain.close();
    });
    for (const type of ['p2wsh', 'p2sh-p2wsh']) {
      it(`should update for ${type}`, async () => {
        const [ring, , mtx, cb] = templateTX(KeyRing.generate(), type, 0, 2, 2);
        const tx = mtx.toTX();
        const psbt = PSBT.fromTX(tx, new CoinView());
        commonAssertion(psbt);
        await chain.fillPSBT(psbt);
        assert.strictEqual(psbt.inputs[0].redeem.code.length, 4);
        assert(ring.script.equals(psbt.inputs[0].redeem));
      });
    }
  });
  */

  describe('Signer', () => {
    const t = ['p2pkh', 'p2sh', 'p2wsh', 'p2wpkh','p2sh-p2wsh', 'p2sh-p2wpkh'];
    for (const type of t) {
      for (const sighash of Object.keys(common.hashTypeByVal)) {
        const val = common.hashTypeByVal[sighash];
        it(`should sign input for ${type} with sighash ${val}`, () => {
          const [ring,,mtx, cb] = templateTX(KeyRing.generate(), type, 0, 2, 2);
          const psbt = PSBT.fromMTX(mtx);
          assert.strictEqual(psbt.inputs[0].signatures.size, 0);
          psbt.inputs[0].nonWitnessUTXO = cb.toTX();
          psbt.inputs[0].sighash = parseInt(sighash);
          psbt.signInput(0, ring);
          assert.strictEqual(psbt.inputs[0].signatures.size, 1);
          const sig = psbt.inputs[0].signatures.get(ring.publicKey);
          assert(sig);
          let prev = cb.outputs[0].script;
          let v = 0;
          if (type === 'p2sh' || type === 'p2sh-p2wpkh')
            prev = psbt.inputs[0].redeem;
          if (type === 'p2wsh' || type === 'p2sh-p2wsh')
            prev = psbt.inputs[0].witness;
          if (type.endsWith('p2wsh') || type.endsWith('p2wpkh'))
            v = 1;
          const dummy = mtx.toTX().clone();
          const value = cb.outputs[0].value;
          assert(
            dummy.checksig(0, prev, value, sig, ring.publicKey, v),
            'malformed signature'
          );
        });
      }
    }
  });

  describe('Combiner', () => {
    it('should merge', () => {});
  });

  describe('Finalizer', () => {});
  describe('TX Extractor', () => {});

  it('should pass the longest test in BIP174', () => {
   /* eslint-disable */
   const d = data.final;
    const master = HDPrivateKey.fromBase58(d.master, 'testnet');
    assert(d.master, master.xprivkey());
    const mtx = new MTX({version: 2});

    mtx.addOutput({
      script: Script.fromRaw(d.out1.script, 'hex'),
      value: Amount.fromBTC(d.out1.value).toValue()
    });
    mtx.addOutput({
      script: Script.fromRaw(d.out2.script, 'hex'),
      value: Amount.fromBTC(d.out2.value).toValue()
    });

    mtx.addInput({
      prevout: {
        hash: util.fromRev(d.in1.txid),
        index: d.in1.index
      }
    });
    mtx.addInput({
      prevout: {
        hash: util.fromRev(d.in2.txid),
        index: d.in2.index
      }
    });
    const psbt = PSBT.fromMTX(mtx);
    let expected = PSBT.fromRaw(d.psbt1, 'base64')
    assertPSBTEqual(psbt, expected);

    // update
    const redeem1 = Script.fromRaw(d.redeem1, 'hex');
    const redeem2 = Script.fromRaw(d.redeem2, 'hex');
    const witness1 = Script.fromRaw(d.witness1, 'hex');
    const prevtx1 = TX.fromRaw(d.prevtx1, 'hex');
    const prevtx2 = TX.fromRaw(d.prevtx2, 'hex');
    const rings = [d.pubkey1, d.pubkey2, d.pubkey3, d.pubkey4, d.pubkey5, d.pubkey6]
      .map(p => KeyRing.fromPublic(Buffer.from(p.hex, 'hex')));
    const keyInfos = [];
    for (const i of [0,1,2,3,4,5]) {
      const path = `m/0'/0'/${i}'`;
      // Just making sure that we can derive expected key from the master.
      const hd = master.derivePath(path);
      assert.bufferEqual(rings[i].publicKey, hd.publicKey);
      
      // usually `PSBT.template` depends on `WalletKey` for setting bip32 path.
      // since bip44 style is the only path the wallet utilizes.
      // So this time we are going to set KeyOriginInfo manually to mimic the
      // wallet for this test.
      const fp = hash160.digest(master.publicKey);
      const fingerPrint = fp.readUInt32BE(0, true);
      keyInfos.push([hd.publicKey, KeyOriginInfo.fromOptions({fingerPrint, path})]);
    }
    rings[0].script = redeem1;
    rings[1].script = redeem1;
    rings[2].script = witness1;
    rings[3].script = witness1;
    rings[2].witness = true;
    rings[3].witness = true;

    psbt.inputs[0].nonWitnessUTXO = prevtx2;
    psbt.inputs[1].witnessUTXO = prevtx1.outputs[1];
    psbt.update(rings);
    // set dummies
    psbt.inputs[0].keyInfo.set(keyInfos[0][0], keyInfos[0][1]);
    psbt.inputs[0].keyInfo.set(keyInfos[1][0], keyInfos[1][1]);
    psbt.inputs[1].keyInfo.set(keyInfos[2][0], keyInfos[2][1]);
    psbt.inputs[1].keyInfo.set(keyInfos[3][0], keyInfos[3][1]);
    psbt.outputs[0].keyInfo.set(keyInfos[4][0], keyInfos[4][1]);
    psbt.outputs[1].keyInfo.set(keyInfos[5][0], keyInfos[5][1]);

    expected = PSBT.fromRaw(d.psbt2, 'base64');
    assertPSBTEqual(psbt, expected);
    const psbttmp = psbt.clone(); // for second signer
    
    // change sighash
    for (const i in psbt.inputs) {
      psbt.inputs[i].sighash = 0;
    }
    expected = PSBT.fromRaw(d.psbt3, 'base64');
    assertPSBTEqual(psbt, expected);

    // signer1
    const privkey7 = KeyRing.fromPrivate(Buffer.from(d.key7, 'hex'));
    const privkey8 = KeyRing.fromPrivate(Buffer.from(d.key8, 'hex'));
    psbt.sign([privkey7, privkey8]);
    expected = PSBT.fromRaw(d.psbt4);
    assertPSBTEqual(psbt, expected);

    // signer2
    const privkey9 = KeyRing.fromPrivate(Buffer.from(d.key9, 'hex'));
    const privkey10 = KeyRing.fromPrivate(Buffer.from(d.key10, 'hex'));
    expected = PSBT.fromRaw(d.psbt5);
    psbttmp.sign([privkey9, privkey10]);
    assertPSBTEqual(psbttmp, expected);

    // combiner
    const psbtCombined1 = psbt.combine(psbttmp);
    const psbtCombined2 = psbttmp.combine(psbt);
    expected = PSBT.fromRaw(d.psbtcombined, 'hex');
    assertPSBTEqual(psbtCombined1, expected);
    assertPSBTEqual(psbtCombined2, expected);

    // finalizer
    const psbtFinalized = psbt.finalize();
    expected = PSBT.fromRaw(d.psbtfinalized, 'hex');
    assertPSBTEqual(psbtFinalized, expected);

    // extractor
    const tx = psbtFinalized.toTX();
    expeted = TX.fromRaw(d.extracted, 'hex');
    // TODO: assert tx equality.
   /* eslint-enable */
  });

  it('can combine psbt with unknown KV-Map correctly', () => {
    const psbt1 = PSBT.fromRaw(data.psbtUnknown1, 'base64');
    const psbt2 = PSBT.fromRaw(data.psbtUnknown2, 'base64');
    const expected = PSBT.fromRaw(data.psbtUnknown3, 'base64');
    const combined = psbt1.combine(psbt2);
    assertPSBTEqual(combined, expected);
  });

  describe('Wallet', () => {
    before(async () => {
      await wdb.open();
    });
    after(async () => {
      await wdb.close();
    });

    it('can fill psbt', async () => {
      const wallet = await wdb.create();
      const ringtmp = await wallet.createReceive();
      const [, , mtx] = templateTX(ringtmp, 'p2wpkh', true);
      const psbt = PSBT.fromMTX(mtx.clone());
      wallet.fillPSBT(psbt);
      // TODO: assert all inputs and outputs are all as expected.
    });
    it('can template path with wallet key', async () => {});
  });
});
