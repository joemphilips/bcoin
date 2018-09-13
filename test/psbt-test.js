/* eslint-env mocha */
'use strict';

const assert = require('./util/assert');
const PSBT = require('../lib/primitives/psbt');
const data = require('./data/psbt.json');

function assertPSBTEqual(actual, expected) {
  assert.bufferEqual(
    actual.mtx.hash(),
    expected.mtx.hash(),
    'tx hash must be same'
  );
  assert(actual.inputs.length === expected.inputs.length);
  assert(actual.outputs.length === expected.outputs.length);

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
    assert(e.sighash === a.sighash, 'sighash must be same');

    assert.bufferMapEqual(a.keyInfo, e.keyInfo);
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

describe('Partially Signed Bitcoin Transaction', () => {
  describe('PSBT', async () => {
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
  });
});
