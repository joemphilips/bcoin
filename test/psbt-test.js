/* eslint-env mocha */
'use strict';

const assert = require('./util/assert');
const PSBT = require('../lib/primitives/psbt');
const data = require('./data/psbt.json');

function assertPSBTEqual(expected, actual) {
  for (const i in expected.inputs) {
    const e = expected.inputs[i];
    const a = actual.inputs[i];
    if (!e.nonWitnessUTXO.isNull()) {
      assert(!a.nonWitnessUTXO.isNull(), 'nonWitnessUTXO must be same');
      assert(
        e.nonWitnessUTXO.hash === a.nonWitnessUTXO.hash,
        'nonWitnessUTXO must be same'
        );
    }

    if (e.witnessUTXO.script.code.length > 0) {
      assert(
        e.witnessUTXO.script.code.length > 0,
        'witnessUTXO must be same'
        );
      assert(
        e.witnessUTXO.equals(a.witnessUTXO),
        'witnessUTXO must be same'
      );
    }

    if (e.redeem.code.length > 0) {
      assert(a.redeem.code.length > 0);
      assert(e.redeem.equals(a.redeem));
    }
  };
}

describe('Partially Signed Bitcoin Transaction', () => {
  describe('PSBT', async () => {
    it('should fail to decode invalid psbt', () => {
      for (const testcase of data.invalid) {
        let err;
        let result;
        try {
          result = PSBT.fromRaw(testcase, 'base64');
        } catch (e) {
          err = e;
        }
        assert.typeOf(err, 'error', `result was ${result}`);
      }
    });

    it('should base64 decode valid psbt', () => {
      for (const testcase of data.valid) {
        const psbt = PSBT.fromRaw(testcase, 'base64');
        assert(psbt, 'failed to decode psbt');
      }
    });

    it('should encode and decode psbt without changing its property', () => {
      for (const testcase of data.valid) {
        const testcaseBuf = Buffer.from(testcase, 'base64');
        const psbt = PSBT.fromRaw(testcaseBuf);
        const raw = psbt.toRaw();
        const psbt2 = PSBT.fromRaw(raw);
        assertPSBTEqual(psbt, psbt2);
      }
    });
  });
});
