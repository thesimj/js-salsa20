"use strict";

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Copyright (c) 2017, Bubelich Mykola
 * https://www.bubelich.com
 *
 * (｡◕‿‿◕｡)
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Salsa20 is a stream cipher submitted to eSTREAM by Daniel J. Bernstein.
 * It is built on a pseudorandom function based on add-rotate-xor (ARX) operations — 32-bit addition,
 * bitwise addition (XOR) and rotation operations. Salsa20 maps a 256-bit key, a 64-bit nonce,
 * and a 64-bit stream position to a 512-bit block of the key stream (a version with a 128-bit key also exists).
 * This gives Salsa20 the unusual advantage that the user can efficiently seek to any position in the key
 * stream in constant time. It offers speeds of around 4–14 cycles per byte in software on modern x86 processors,
 * and reasonable hardware performance. It is not patented, and Bernstein has written several
 * public domain implementations optimized for common architectures.
 */

var JSSalsa20 = function () {

  /**
   * Construct SalSa20 instance with key and nonce
   * Key should be Uint8Array with 32 bytes
   * None should be Uint8Array with 8 bytes
   *
   *
   * @throws {Error}
   * @param {Uint8Array} key
   * @param {Uint8Array} nonce
   */
  function JSSalsa20(key, nonce) {
    _classCallCheck(this, JSSalsa20);

    if (key.length !== 32) {
      throw new Error("Key should be 32 byte array!");
    }

    if (nonce.length !== 8) {
      throw new Error("Nonce should be 8 byte array!");
    }

    this.rounds = 20;
    this.sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    this.param = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // set sigma constant //
    this.param[0] = this.sigma[0];
    this.param[5] = this.sigma[1];
    this.param[10] = this.sigma[2];
    this.param[15] = this.sigma[3];

    // set key //
    this.param[1] = this._get32(key, 0);
    this.param[2] = this._get32(key, 4);
    this.param[3] = this._get32(key, 8);
    this.param[4] = this._get32(key, 12);

    // set nonce //
    this.param[6] = this._get32(nonce, 0);
    this.param[7] = this._get32(nonce, 4);

    // set counter //
    this.param[8] = 0;
    this.param[9] = 0;

    // set key again //
    this.param[11] = this._get32(key, 16);
    this.param[12] = this._get32(key, 20);
    this.param[13] = this._get32(key, 24);
    this.param[14] = this._get32(key, 28);

    // log param
    // this._log(this.param, "param");

    // init block //
    this.block = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // internal byte counter //
    this.byteCounter = 0;
  }

  /**
   *  Encrypt or Decrypt data with key and nonce
   *
   * @param {Uint8Array} data
   * @return {Uint8Array}
   * @private
   */


  _createClass(JSSalsa20, [{
    key: "_update",
    value: function _update(data) {

      if (!(data instanceof Uint8Array) || data.length === 0) {
        throw new Error("Data should be type of Uint8Array and not empty!");
      }

      var output = new Uint8Array(data.length);

      // core function, build block and xor with input data //
      for (var i = 0; i < data.length; i++) {
        if (this.byteCounter === 0 || this.byteCounter === 64) {
          this._salsa();
          this._counterIncrement();
          this.byteCounter = 0;
        }

        output[i] = data[i] ^ this.block[this.byteCounter++];
      }

      return output;
    }

    /**
     *  Encrypt data with key and nonce
     *
     * @param {Uint8Array} data
     * @return {Uint8Array}
     */

  }, {
    key: "encrypt",
    value: function encrypt(data) {
      return this._update(data);
    }

    /**
     *  Decrypt data with key and nonce
     *
     * @param {Uint8Array} data
     * @return {Uint8Array}
     */

  }, {
    key: "decrypt",
    value: function decrypt(data) {
      return this._update(data);
    }
  }, {
    key: "_counterIncrement",
    value: function _counterIncrement() {
      // Max possible blocks is 2^64
      this.param[8] = this.param[8] + 1 >>> 0;
      if (this.param[8] == 0) {
        this.param[9] = this.param[9] + 1 >>> 0;
      }
    }
  }, {
    key: "_salsa",
    value: function _salsa() {
      var mix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      var i = 0,
          b = 0;

      // copy param array to mix //
      for (i = 0; i < 16; i++) {
        mix[i] = this.param[i];
      }

      // mix rounds //
      for (i = 0; i < this.rounds; i += 2) {
        this._quarter(mix, 4, 8, 12, 0);
        this._quarter(mix, 9, 13, 1, 5);
        this._quarter(mix, 14, 2, 6, 10);
        this._quarter(mix, 3, 7, 11, 15);
        this._quarter(mix, 1, 2, 3, 0);
        this._quarter(mix, 6, 7, 4, 5);
        this._quarter(mix, 11, 8, 9, 10);
        this._quarter(mix, 12, 13, 14, 15);
      }

      for (i = 0; i < 16; i++) {
        // add
        mix[i] += this.param[i];

        // store
        this.block[b++] = mix[i] & 0xFF;
        this.block[b++] = mix[i] >>> 8 & 0xFF;
        this.block[b++] = mix[i] >>> 16 & 0xFF;
        this.block[b++] = mix[i] >>> 24 & 0xFF;
      }

      // this._log(mix, "final mix");
    }

    /**
     * Salsa quarter function
     *
     * @param {[number]} data
     * @param {number} a
     * @param {number} b
     * @param {number} c
     * @param {number} d
     * @private
     */

  }, {
    key: "_quarter",
    value: function _quarter(data, a, b, c, d) {
      // >>> 0 convert double to unsigned integer 32 bit
      data[a] = (data[a] ^ this._rotl(data[d] + data[c], 7)) >>> 0;
      data[b] = (data[b] ^ this._rotl(data[a] + data[d], 9)) >>> 0;
      data[c] = (data[c] ^ this._rotl(data[b] + data[a], 13)) >>> 0;
      data[d] = (data[d] ^ this._rotl(data[c] + data[b], 18)) >>> 0;
    }

    /**
     * Little-endian to uint 32 bytes
     *
     * @param {Uint8Array|[number]} data
     * @param {number} index
     * @return {number}
     * @private
     */

  }, {
    key: "_get32",
    value: function _get32(data, index) {
      return data[index++] ^ data[index++] << 8 ^ data[index++] << 16 ^ data[index] << 24;
    }

    /**
     * Cyclic left rotation
     *
     * @param {number} data
     * @param {number} shift
     * @return {number}
     * @private
     */

  }, {
    key: "_rotl",
    value: function _rotl(data, shift) {
      return data << shift | data >>> 32 - shift;
    }

    /**
     * Helper log function
     *
     * @param {[number]} data
     * @param {String} message
     * @private
     */

  }, {
    key: "_log",
    value: function _log(data) {
      var message = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : "";


      console.log("\n log: " + message);

      for (var i = 0; i < data.length; i += 4) {
        var a = ("0x00000000" + data[i].toString(16)).slice(-8);
        var b = ("0x00000000" + data[i + 1].toString(16)).slice(-8);
        var c = ("0x00000000" + data[i + 2].toString(16)).slice(-8);
        var d = ("0x00000000" + data[i + 3].toString(16)).slice(-8);

        console.log(a, b, c, d);
      }
    }
  }]);

  return JSSalsa20;
}();

// EXPORT //


if (typeof module !== "undefined" && module.exports) {
  module.exports = JSSalsa20;
}

//# sourceMappingURL=data:application/json;base64,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Ozs7OzswQkFRTSxJLEVBQU0sSyxFQUFPO0FBQ2pCLGFBQVMsUUFBUSxLQUFULEdBQW1CLFNBQVUsS0FBSyxLQUExQztBQUNEOztBQUVEOzs7Ozs7Ozs7O3lCQU9LLEksRUFBb0I7QUFBQSxVQUFkLE9BQWMsdUVBQUosRUFBSTs7O0FBRXZCLGNBQVEsR0FBUixDQUFZLGFBQWEsT0FBekI7O0FBRUEsV0FBSyxJQUFJLElBQUksQ0FBYixFQUFnQixJQUFJLEtBQUssTUFBekIsRUFBaUMsS0FBSyxDQUF0QyxFQUF5QztBQUN2QyxZQUFNLElBQUksQ0FBQyxlQUFlLEtBQUssQ0FBTCxFQUFRLFFBQVIsQ0FBaUIsRUFBakIsQ0FBaEIsRUFBc0MsS0FBdEMsQ0FBNEMsQ0FBQyxDQUE3QyxDQUFWO0FBQ0EsWUFBTSxJQUFJLENBQUMsZUFBZSxLQUFLLElBQUksQ0FBVCxFQUFZLFFBQVosQ0FBcUIsRUFBckIsQ0FBaEIsRUFBMEMsS0FBMUMsQ0FBZ0QsQ0FBQyxDQUFqRCxDQUFWO0FBQ0EsWUFBTSxJQUFJLENBQUMsZUFBZSxLQUFLLElBQUksQ0FBVCxFQUFZLFFBQVosQ0FBcUIsRUFBckIsQ0FBaEIsRUFBMEMsS0FBMUMsQ0FBZ0QsQ0FBQyxDQUFqRCxDQUFWO0FBQ0EsWUFBTSxJQUFJLENBQUMsZUFBZSxLQUFLLElBQUksQ0FBVCxFQUFZLFFBQVosQ0FBcUIsRUFBckIsQ0FBaEIsRUFBMEMsS0FBMUMsQ0FBZ0QsQ0FBQyxDQUFqRCxDQUFWOztBQUVBLGdCQUFRLEdBQVIsQ0FBWSxDQUFaLEVBQWUsQ0FBZixFQUFrQixDQUFsQixFQUFxQixDQUFyQjtBQUNEO0FBQ0Y7Ozs7OztBQUdIOzs7QUFDQSxJQUFJLE9BQU8sTUFBUCxLQUFrQixXQUFsQixJQUFpQyxPQUFPLE9BQTVDLEVBQXFEO0FBQ25ELFNBQU8sT0FBUCxHQUFpQixTQUFqQjtBQUNEIiwiZmlsZSI6Impzc2Fsc2EyMC5qcyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBDb3B5cmlnaHQgKGMpIDIwMTcsIEJ1YmVsaWNoIE15a29sYVxuICogaHR0cHM6Ly93d3cuYnViZWxpY2guY29tXG4gKlxuICogKO+9oeKXleKAv+KAv+KXle+9oSlcbiAqXG4gKiBBbGwgcmlnaHRzIHJlc2VydmVkLlxuICpcbiAqIFJlZGlzdHJpYnV0aW9uIGFuZCB1c2UgaW4gc291cmNlIGFuZCBiaW5hcnkgZm9ybXMsIHdpdGggb3Igd2l0aG91dFxuICogbW9kaWZpY2F0aW9uLCBhcmUgcGVybWl0dGVkIHByb3ZpZGVkIHRoYXQgdGhlIGZvbGxvd2luZyBjb25kaXRpb25zIGFyZSBtZXQ6XG4gKlxuICogUmVkaXN0cmlidXRpb25zIG9mIHNvdXJjZSBjb2RlIG11c3QgcmV0YWluIHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlLFxuICogdGhpcyBsaXN0IG9mIGNvbmRpdGlvbnMgYW5kIHRoZSBmb2xsb3dpbmcgZGlzY2xhaW1lci5cbiAqXG4gKiBSZWRpc3RyaWJ1dGlvbnMgaW4gYmluYXJ5IGZvcm0gbXVzdCByZXByb2R1Y2UgdGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UsXG4gKiB0aGlzIGxpc3Qgb2YgY29uZGl0aW9ucyBhbmQgdGhlIGZvbGxvd2luZyBkaXNjbGFpbWVyIGluIHRoZSBkb2N1bWVudGF0aW9uXG4gKiBhbmQvb3Igb3RoZXIgbWF0ZXJpYWxzIHByb3ZpZGVkIHdpdGggdGhlIGRpc3RyaWJ1dGlvbi5cbiAqXG4gKiBOZWl0aGVyIHRoZSBuYW1lIG9mIHRoZSBjb3B5cmlnaHQgaG9sZGVyIG5vciB0aGUgbmFtZXMgb2YgaXRzIGNvbnRyaWJ1dG9yc1xuICogbWF5IGJlIHVzZWQgdG8gZW5kb3JzZSBvciBwcm9tb3RlIHByb2R1Y3RzIGRlcml2ZWQgZnJvbSB0aGlzIHNvZnR3YXJlIHdpdGhvdXRcbiAqIHNwZWNpZmljIHByaW9yIHdyaXR0ZW4gcGVybWlzc2lvbi5cbiAqXG4gKiBUSElTIFNPRlRXQVJFIElTIFBST1ZJREVEIEJZIFRIRSBDT1BZUklHSFQgSE9MREVSIEFORCBDT05UUklCVVRPUlMgXCJBUyBJU1wiXG4gKiBBTkQgQU5ZIEVYUFJFU1MgT1IgSU1QTElFRCBXQVJSQU5USUVTLCBJTkNMVURJTkcsIEJVVCBOT1QgTElNSVRFRCBUTywgVEhFXG4gKiBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZIEFORCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRVxuICogQVJFIERJU0NMQUlNRUQuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBDT1BZUklHSFQgT1dORVIgT1IgQ09OVFJJQlVUT1JTIEJFXG4gKiBMSUFCTEUgRk9SIEFOWSBESVJFQ1QsIElORElSRUNULCBJTkNJREVOVEFMLCBTUEVDSUFMLCBFWEVNUExBUlksIE9SXG4gKiBDT05TRVFVRU5USUFMIERBTUFHRVMgKElOQ0xVRElORywgQlVUIE5PVCBMSU1JVEVEIFRPLCBQUk9DVVJFTUVOVCBPRlxuICogU1VCU1RJVFVURSBHT09EUyBPUiBTRVJWSUNFUzsgTE9TUyBPRiBVU0UsIERBVEEsIE9SIFBST0ZJVFM7IE9SIEJVU0lORVNTXG4gKiBJTlRFUlJVUFRJT04pIEhPV0VWRVIgQ0FVU0VEIEFORCBPTiBBTlkgVEhFT1JZIE9GIExJQUJJTElUWSwgV0hFVEhFUiBJTlxuICogQ09OVFJBQ1QsIFNUUklDVCBMSUFCSUxJVFksIE9SIFRPUlQgKElOQ0xVRElORyBORUdMSUdFTkNFIE9SIE9USEVSV0lTRSlcbiAqIEFSSVNJTkcgSU4gQU5ZIFdBWSBPVVQgT0YgVEhFIFVTRSBPRiBUSElTIFNPRlRXQVJFLCBFVkVOIElGIEFEVklTRUQgT0YgVEhFXG4gKiBQT1NTSUJJTElUWSBPRiBTVUNIIERBTUFHRS5cbiAqXG4gKiBTYWxzYTIwIGlzIGEgc3RyZWFtIGNpcGhlciBzdWJtaXR0ZWQgdG8gZVNUUkVBTSBieSBEYW5pZWwgSi4gQmVybnN0ZWluLlxuICogSXQgaXMgYnVpbHQgb24gYSBwc2V1ZG9yYW5kb20gZnVuY3Rpb24gYmFzZWQgb24gYWRkLXJvdGF0ZS14b3IgKEFSWCkgb3BlcmF0aW9ucyDigJQgMzItYml0IGFkZGl0aW9uLFxuICogYml0d2lzZSBhZGRpdGlvbiAoWE9SKSBhbmQgcm90YXRpb24gb3BlcmF0aW9ucy4gU2Fsc2EyMCBtYXBzIGEgMjU2LWJpdCBrZXksIGEgNjQtYml0IG5vbmNlLFxuICogYW5kIGEgNjQtYml0IHN0cmVhbSBwb3NpdGlvbiB0byBhIDUxMi1iaXQgYmxvY2sgb2YgdGhlIGtleSBzdHJlYW0gKGEgdmVyc2lvbiB3aXRoIGEgMTI4LWJpdCBrZXkgYWxzbyBleGlzdHMpLlxuICogVGhpcyBnaXZlcyBTYWxzYTIwIHRoZSB1bnVzdWFsIGFkdmFudGFnZSB0aGF0IHRoZSB1c2VyIGNhbiBlZmZpY2llbnRseSBzZWVrIHRvIGFueSBwb3NpdGlvbiBpbiB0aGUga2V5XG4gKiBzdHJlYW0gaW4gY29uc3RhbnQgdGltZS4gSXQgb2ZmZXJzIHNwZWVkcyBvZiBhcm91bmQgNOKAkzE0IGN5Y2xlcyBwZXIgYnl0ZSBpbiBzb2Z0d2FyZSBvbiBtb2Rlcm4geDg2IHByb2Nlc3NvcnMsXG4gKiBhbmQgcmVhc29uYWJsZSBoYXJkd2FyZSBwZXJmb3JtYW5jZS4gSXQgaXMgbm90IHBhdGVudGVkLCBhbmQgQmVybnN0ZWluIGhhcyB3cml0dGVuIHNldmVyYWxcbiAqIHB1YmxpYyBkb21haW4gaW1wbGVtZW50YXRpb25zIG9wdGltaXplZCBmb3IgY29tbW9uIGFyY2hpdGVjdHVyZXMuXG4gKi9cblxuY2xhc3MgSlNTYWxzYTIwIHtcblxuICAvKipcbiAgICogQ29uc3RydWN0IFNhbFNhMjAgaW5zdGFuY2Ugd2l0aCBrZXkgYW5kIG5vbmNlXG4gICAqIEtleSBzaG91bGQgYmUgVWludDhBcnJheSB3aXRoIDMyIGJ5dGVzXG4gICAqIE5vbmUgc2hvdWxkIGJlIFVpbnQ4QXJyYXkgd2l0aCA4IGJ5dGVzXG4gICAqXG4gICAqXG4gICAqIEB0aHJvd3Mge0Vycm9yfVxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IGtleVxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IG5vbmNlXG4gICAqL1xuICBjb25zdHJ1Y3RvcihrZXksIG5vbmNlKSB7XG4gICAgaWYgKGtleS5sZW5ndGggIT09IDMyKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJLZXkgc2hvdWxkIGJlIDMyIGJ5dGUgYXJyYXkhXCIpO1xuICAgIH1cblxuICAgIGlmIChub25jZS5sZW5ndGggIT09IDgpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIk5vbmNlIHNob3VsZCBiZSA4IGJ5dGUgYXJyYXkhXCIpO1xuICAgIH1cblxuICAgIHRoaXMucm91bmRzID0gMjA7XG4gICAgdGhpcy5zaWdtYSA9IFsweDYxNzA3ODY1LCAweDMzMjA2NDZlLCAweDc5NjIyZDMyLCAweDZiMjA2NTc0XTtcblxuICAgIHRoaXMucGFyYW0gPSBbMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMF07XG5cbiAgICAvLyBzZXQgc2lnbWEgY29uc3RhbnQgLy9cbiAgICB0aGlzLnBhcmFtWzBdID0gdGhpcy5zaWdtYVswXTtcbiAgICB0aGlzLnBhcmFtWzVdID0gdGhpcy5zaWdtYVsxXTtcbiAgICB0aGlzLnBhcmFtWzEwXSA9IHRoaXMuc2lnbWFbMl07XG4gICAgdGhpcy5wYXJhbVsxNV0gPSB0aGlzLnNpZ21hWzNdO1xuXG4gICAgLy8gc2V0IGtleSAvL1xuICAgIHRoaXMucGFyYW1bMV0gPSB0aGlzLl9nZXQzMihrZXksIDApO1xuICAgIHRoaXMucGFyYW1bMl0gPSB0aGlzLl9nZXQzMihrZXksIDQpO1xuICAgIHRoaXMucGFyYW1bM10gPSB0aGlzLl9nZXQzMihrZXksIDgpO1xuICAgIHRoaXMucGFyYW1bNF0gPSB0aGlzLl9nZXQzMihrZXksIDEyKTtcblxuICAgIC8vIHNldCBub25jZSAvL1xuICAgIHRoaXMucGFyYW1bNl0gPSB0aGlzLl9nZXQzMihub25jZSwgMCk7XG4gICAgdGhpcy5wYXJhbVs3XSA9IHRoaXMuX2dldDMyKG5vbmNlLCA0KTtcblxuICAgIC8vIHNldCBjb3VudGVyIC8vXG4gICAgdGhpcy5wYXJhbVs4XSA9IDA7XG4gICAgdGhpcy5wYXJhbVs5XSA9IDA7XG5cbiAgICAvLyBzZXQga2V5IGFnYWluIC8vXG4gICAgdGhpcy5wYXJhbVsxMV0gPSB0aGlzLl9nZXQzMihrZXksIDE2KTtcbiAgICB0aGlzLnBhcmFtWzEyXSA9IHRoaXMuX2dldDMyKGtleSwgMjApO1xuICAgIHRoaXMucGFyYW1bMTNdID0gdGhpcy5fZ2V0MzIoa2V5LCAyNCk7XG4gICAgdGhpcy5wYXJhbVsxNF0gPSB0aGlzLl9nZXQzMihrZXksIDI4KTtcblxuICAgIC8vIGxvZyBwYXJhbVxuICAgIC8vIHRoaXMuX2xvZyh0aGlzLnBhcmFtLCBcInBhcmFtXCIpO1xuXG4gICAgLy8gaW5pdCBibG9jayAvL1xuICAgIHRoaXMuYmxvY2sgPSBbXG4gICAgICAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLFxuICAgICAgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCxcbiAgICBdO1xuXG4gICAgLy8gaW50ZXJuYWwgYnl0ZSBjb3VudGVyIC8vXG4gICAgdGhpcy5ieXRlQ291bnRlciA9IDA7XG4gIH1cblxuICAvKipcbiAgICogIEVuY3J5cHQgb3IgRGVjcnlwdCBkYXRhIHdpdGgga2V5IGFuZCBub25jZVxuICAgKlxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IGRhdGFcbiAgICogQHJldHVybiB7VWludDhBcnJheX1cbiAgICogQHByaXZhdGVcbiAgICovXG4gIF91cGRhdGUoZGF0YSkge1xuXG4gICAgaWYgKCEoZGF0YSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHx8IGRhdGEubGVuZ3RoID09PSAwKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJEYXRhIHNob3VsZCBiZSB0eXBlIG9mIFVpbnQ4QXJyYXkgYW5kIG5vdCBlbXB0eSFcIik7XG4gICAgfVxuXG4gICAgY29uc3Qgb3V0cHV0ID0gbmV3IFVpbnQ4QXJyYXkoZGF0YS5sZW5ndGgpO1xuXG4gICAgLy8gY29yZSBmdW5jdGlvbiwgYnVpbGQgYmxvY2sgYW5kIHhvciB3aXRoIGlucHV0IGRhdGEgLy9cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGRhdGEubGVuZ3RoOyBpKyspIHtcbiAgICAgIGlmICh0aGlzLmJ5dGVDb3VudGVyID09PSAwIHx8IHRoaXMuYnl0ZUNvdW50ZXIgPT09IDY0KSB7XG4gICAgICAgIHRoaXMuX3NhbHNhKCk7XG4gICAgICAgIHRoaXMuX2NvdW50ZXJJbmNyZW1lbnQoKTtcbiAgICAgICAgdGhpcy5ieXRlQ291bnRlciA9IDA7XG4gICAgICB9XG5cbiAgICAgIG91dHB1dFtpXSA9IGRhdGFbaV0gXiB0aGlzLmJsb2NrW3RoaXMuYnl0ZUNvdW50ZXIrK107XG4gICAgfVxuXG4gICAgcmV0dXJuIG91dHB1dDtcbiAgfVxuXG4gIC8qKlxuICAgKiAgRW5jcnlwdCBkYXRhIHdpdGgga2V5IGFuZCBub25jZVxuICAgKlxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IGRhdGFcbiAgICogQHJldHVybiB7VWludDhBcnJheX1cbiAgICovXG4gIGVuY3J5cHQoZGF0YSkge1xuICAgIHJldHVybiB0aGlzLl91cGRhdGUoZGF0YSk7XG4gIH1cblxuICAvKipcbiAgICogIERlY3J5cHQgZGF0YSB3aXRoIGtleSBhbmQgbm9uY2VcbiAgICpcbiAgICogQHBhcmFtIHtVaW50OEFycmF5fSBkYXRhXG4gICAqIEByZXR1cm4ge1VpbnQ4QXJyYXl9XG4gICAqL1xuICBkZWNyeXB0KGRhdGEpIHtcbiAgICByZXR1cm4gdGhpcy5fdXBkYXRlKGRhdGEpO1xuICB9XG5cbiAgX2NvdW50ZXJJbmNyZW1lbnQoKSB7XG4gICAgLy8gTWF4IHBvc3NpYmxlIGJsb2NrcyBpcyAyXjY0XG4gICAgdGhpcy5wYXJhbVs4XSA9ICh0aGlzLnBhcmFtWzhdICsgMSkgPj4+IDA7XG4gICAgaWYgKHRoaXMucGFyYW1bOF0gPT0gMCkge1xuICAgICAgdGhpcy5wYXJhbVs5XSA9ICh0aGlzLnBhcmFtWzldICsgMSkgPj4+IDA7XG4gICAgfVxuICB9XG5cbiAgX3NhbHNhKCkge1xuICAgIGNvbnN0IG1peCA9IFswLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwXTtcbiAgICBsZXQgaSA9IDAsIGIgPSAwO1xuXG4gICAgLy8gY29weSBwYXJhbSBhcnJheSB0byBtaXggLy9cbiAgICBmb3IgKGkgPSAwOyBpIDwgMTY7IGkrKykge1xuICAgICAgbWl4W2ldID0gdGhpcy5wYXJhbVtpXTtcbiAgICB9XG5cbiAgICAvLyBtaXggcm91bmRzIC8vXG4gICAgZm9yIChpID0gMDsgaSA8IHRoaXMucm91bmRzOyBpICs9IDIpIHtcbiAgICAgIHRoaXMuX3F1YXJ0ZXIobWl4LCA0LCA4LCAxMiwgMCk7XG4gICAgICB0aGlzLl9xdWFydGVyKG1peCwgOSwgMTMsIDEsIDUpO1xuICAgICAgdGhpcy5fcXVhcnRlcihtaXgsIDE0LCAyLCA2LCAxMCk7XG4gICAgICB0aGlzLl9xdWFydGVyKG1peCwgMywgNywgMTEsIDE1KTtcbiAgICAgIHRoaXMuX3F1YXJ0ZXIobWl4LCAxLCAyLCAzLCAwKTtcbiAgICAgIHRoaXMuX3F1YXJ0ZXIobWl4LCA2LCA3LCA0LCA1KTtcbiAgICAgIHRoaXMuX3F1YXJ0ZXIobWl4LCAxMSwgOCwgOSwgMTApO1xuICAgICAgdGhpcy5fcXVhcnRlcihtaXgsIDEyLCAxMywgMTQsIDE1KTtcbiAgICB9XG5cbiAgICBmb3IgKGkgPSAwOyBpIDwgMTY7IGkrKykge1xuICAgICAgLy8gYWRkXG4gICAgICBtaXhbaV0gKz0gdGhpcy5wYXJhbVtpXTtcblxuICAgICAgLy8gc3RvcmVcbiAgICAgIHRoaXMuYmxvY2tbYisrXSA9IG1peFtpXSAmIDB4RkY7XG4gICAgICB0aGlzLmJsb2NrW2IrK10gPSAobWl4W2ldID4+PiA4KSAmIDB4RkY7XG4gICAgICB0aGlzLmJsb2NrW2IrK10gPSAobWl4W2ldID4+PiAxNikgJiAweEZGO1xuICAgICAgdGhpcy5ibG9ja1tiKytdID0gKG1peFtpXSA+Pj4gMjQpICYgMHhGRjtcbiAgICB9XG5cbiAgICAvLyB0aGlzLl9sb2cobWl4LCBcImZpbmFsIG1peFwiKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBTYWxzYSBxdWFydGVyIGZ1bmN0aW9uXG4gICAqXG4gICAqIEBwYXJhbSB7W251bWJlcl19IGRhdGFcbiAgICogQHBhcmFtIHtudW1iZXJ9IGFcbiAgICogQHBhcmFtIHtudW1iZXJ9IGJcbiAgICogQHBhcmFtIHtudW1iZXJ9IGNcbiAgICogQHBhcmFtIHtudW1iZXJ9IGRcbiAgICogQHByaXZhdGVcbiAgICovXG4gIF9xdWFydGVyKGRhdGEsIGEsIGIsIGMsIGQpIHtcbiAgICAvLyA+Pj4gMCBjb252ZXJ0IGRvdWJsZSB0byB1bnNpZ25lZCBpbnRlZ2VyIDMyIGJpdFxuICAgIGRhdGFbYV0gPSAoZGF0YVthXSBeIHRoaXMuX3JvdGwoZGF0YVtkXSArIGRhdGFbY10sIDcpKSA+Pj4gMDtcbiAgICBkYXRhW2JdID0gKGRhdGFbYl0gXiB0aGlzLl9yb3RsKGRhdGFbYV0gKyBkYXRhW2RdLCA5KSkgPj4+IDA7XG4gICAgZGF0YVtjXSA9IChkYXRhW2NdIF4gdGhpcy5fcm90bChkYXRhW2JdICsgZGF0YVthXSwgMTMpKSA+Pj4gMDtcbiAgICBkYXRhW2RdID0gKGRhdGFbZF0gXiB0aGlzLl9yb3RsKGRhdGFbY10gKyBkYXRhW2JdLCAxOCkpID4+PiAwO1xuICB9XG5cbiAgLyoqXG4gICAqIExpdHRsZS1lbmRpYW4gdG8gdWludCAzMiBieXRlc1xuICAgKlxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl8W251bWJlcl19IGRhdGFcbiAgICogQHBhcmFtIHtudW1iZXJ9IGluZGV4XG4gICAqIEByZXR1cm4ge251bWJlcn1cbiAgICogQHByaXZhdGVcbiAgICovXG4gIF9nZXQzMihkYXRhLCBpbmRleCkge1xuICAgIHJldHVybiBkYXRhW2luZGV4KytdIF4gKGRhdGFbaW5kZXgrK10gPDwgOCkgXiAoZGF0YVtpbmRleCsrXSA8PCAxNikgXiAoZGF0YVtpbmRleF0gPDwgMjQpO1xuICB9XG5cbiAgLyoqXG4gICAqIEN5Y2xpYyBsZWZ0IHJvdGF0aW9uXG4gICAqXG4gICAqIEBwYXJhbSB7bnVtYmVyfSBkYXRhXG4gICAqIEBwYXJhbSB7bnVtYmVyfSBzaGlmdFxuICAgKiBAcmV0dXJuIHtudW1iZXJ9XG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBfcm90bChkYXRhLCBzaGlmdCkge1xuICAgIHJldHVybiAoKGRhdGEgPDwgc2hpZnQpIHwgKGRhdGEgPj4+ICgzMiAtIHNoaWZ0KSkpO1xuICB9XG5cbiAgLyoqXG4gICAqIEhlbHBlciBsb2cgZnVuY3Rpb25cbiAgICpcbiAgICogQHBhcmFtIHtbbnVtYmVyXX0gZGF0YVxuICAgKiBAcGFyYW0ge1N0cmluZ30gbWVzc2FnZVxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgX2xvZyhkYXRhLCBtZXNzYWdlID0gXCJcIikge1xuXG4gICAgY29uc29sZS5sb2coXCJcXG4gbG9nOiBcIiArIG1lc3NhZ2UpO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBkYXRhLmxlbmd0aDsgaSArPSA0KSB7XG4gICAgICBjb25zdCBhID0gKFwiMHgwMDAwMDAwMFwiICsgZGF0YVtpXS50b1N0cmluZygxNikpLnNsaWNlKC04KTtcbiAgICAgIGNvbnN0IGIgPSAoXCIweDAwMDAwMDAwXCIgKyBkYXRhW2kgKyAxXS50b1N0cmluZygxNikpLnNsaWNlKC04KTtcbiAgICAgIGNvbnN0IGMgPSAoXCIweDAwMDAwMDAwXCIgKyBkYXRhW2kgKyAyXS50b1N0cmluZygxNikpLnNsaWNlKC04KTtcbiAgICAgIGNvbnN0IGQgPSAoXCIweDAwMDAwMDAwXCIgKyBkYXRhW2kgKyAzXS50b1N0cmluZygxNikpLnNsaWNlKC04KTtcblxuICAgICAgY29uc29sZS5sb2coYSwgYiwgYywgZCk7XG4gICAgfVxuICB9XG59XG5cbi8vIEVYUE9SVCAvL1xuaWYgKHR5cGVvZiBtb2R1bGUgIT09IFwidW5kZWZpbmVkXCIgJiYgbW9kdWxlLmV4cG9ydHMpIHtcbiAgbW9kdWxlLmV4cG9ydHMgPSBKU1NhbHNhMjA7XG59XG4iXX0=