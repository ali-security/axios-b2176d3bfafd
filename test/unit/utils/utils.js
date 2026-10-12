import assert from 'assert';
import utils from '../../../lib/utils.js';
import FormData from 'form-data';
import stream from 'stream';

describe('utils', function (){
  it('should validate Stream', function () {
    assert.strictEqual(utils.isStream(new stream.Readable()),true);
    assert.strictEqual(utils.isStream({ foo: 'bar' }),false);
  });

  it('should validate Buffer', function () {
    assert.strictEqual(utils.isBuffer(Buffer.from('a')),true);
    assert.strictEqual(utils.isBuffer(null),false);
    assert.strictEqual(utils.isBuffer(undefined),false);
  });

  describe('utils::isFormData', function () {
    it('should detect the FormData instance provided by the `form-data` package', function () {
      [1, 'str', {}, new RegExp()].forEach(function (thing) {
        assert.equal(utils.isFormData(thing), false);
      });
      assert.equal(utils.isFormData(new FormData()), true);
    });

    it('should not call toString method on built-in objects instances', () => {
      const buf = Buffer.from('123');

      buf.toString = () => assert.fail('should not be called');

      assert.equal(utils.isFormData(buf), false);
    });

    it('should not call toString method on built-in objects instances, even if append method exists', () => {
      const buf = Buffer.from('123');

      buf.append = () => {};

      buf.toString = () => assert.fail('should not be called');

      assert.equal(utils.isFormData(buf), false);
    });

    it('should detect custom FormData instances by toStringTag signature and append method presence', () => {
      class FormData {
        append(){

        }

        get [Symbol.toStringTag]() {
          return 'FormData';
        }
      }
      assert.equal(utils.isFormData(new FormData()), true);
    });

    describe('prototype pollution (GHSA-6chq-wfr3-2hj9)', () => {
      const originalToString = Object.getOwnPropertyDescriptor(Object.prototype, 'toString');

      afterEach(() => {
        delete Object.prototype.append;
        delete Object.prototype[Symbol.toStringTag];
        Object.defineProperty(Object.prototype, 'toString', originalToString);
      });

      it('should not treat a plain object as FormData when Object.prototype carries append and toStringTag', () => {
        Object.prototype.append = () => {};
        Object.prototype[Symbol.toStringTag] = 'FormData';

        assert.strictEqual(utils.isFormData({userId: 42}), false);
      });

      it('should not treat a plain object as FormData when Object.prototype carries append and toString', () => {
        Object.prototype.append = () => {};
        Object.prototype.toString = () => '[object FormData]';

        const result = utils.isFormData({userId: 42});

        Object.defineProperty(Object.prototype, 'toString', originalToString);

        assert.strictEqual(result, false);
      });

      it('should still detect genuine FormData instances while Object.prototype is polluted', () => {
        Object.prototype.append = () => {};
        Object.prototype[Symbol.toStringTag] = 'FormData';

        assert.strictEqual(utils.isFormData(new FormData()), true);
      });
    });
  });

  describe('toJSON', function (){
    it('should convert to a plain object without circular references', function () {
      const obj= {a: [0]}
      const source = {x:1, y:2, obj};
      source.circular1 = source;
      obj.a[1] = obj;

      assert.deepStrictEqual(utils.toJSONObject(source), {
        x: 1, y:2, obj: {a: [0]}
      });
    });

    it('should use objects with defined toJSON method without rebuilding', function () {
      const objProp = {};
      const obj= {objProp, toJSON(){
        return {ok: 1}
      }};
      const source = {x:1, y:2, obj};

      const jsonObject = utils.toJSONObject(source);

      assert.strictEqual(jsonObject.obj.objProp, objProp);
      assert.strictEqual(JSON.stringify(jsonObject), JSON.stringify({x: 1, y:2, obj: {ok: 1}}))
    });
  });
});
