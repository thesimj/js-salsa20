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
 * General information
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

    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error("Key should be 32 byte array!");
    }

    if (!(nonce instanceof Uint8Array) || nonce.length !== 8) {
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
        throw new Error("Data should be type of bytes (Uint8Array) and not empty!");
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
  }]);

  return JSSalsa20;
}();

// EXPORT //


if (typeof module !== "undefined" && module.exports) {
  module.exports = JSSalsa20;
}

//# sourceMappingURL=data:application/json;base64,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QWdFLEtBQUssS0FBTCxLQUFlLEVBQXRGO0FBQ0Q7O0FBRUQ7Ozs7Ozs7Ozs7OzBCQVFNLEksRUFBTSxLLEVBQU87QUFDakIsYUFBUyxRQUFRLEtBQVQsR0FBbUIsU0FBVSxLQUFLLEtBQTFDO0FBQ0Q7Ozs7OztBQUdIOzs7QUFDQSxJQUFJLE9BQU8sTUFBUCxLQUFrQixXQUFsQixJQUFpQyxPQUFPLE9BQTVDLEVBQXFEO0FBQ25ELFNBQU8sT0FBUCxHQUFpQixTQUFqQjtBQUNEIiwiZmlsZSI6Impzc2Fsc2EyMC5qcyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBDb3B5cmlnaHQgKGMpIDIwMTcsIEJ1YmVsaWNoIE15a29sYVxuICogaHR0cHM6Ly93d3cuYnViZWxpY2guY29tXG4gKlxuICogKO+9oeKXleKAv+KAv+KXle+9oSlcbiAqXG4gKiBBbGwgcmlnaHRzIHJlc2VydmVkLlxuICpcbiAqIFJlZGlzdHJpYnV0aW9uIGFuZCB1c2UgaW4gc291cmNlIGFuZCBiaW5hcnkgZm9ybXMsIHdpdGggb3Igd2l0aG91dFxuICogbW9kaWZpY2F0aW9uLCBhcmUgcGVybWl0dGVkIHByb3ZpZGVkIHRoYXQgdGhlIGZvbGxvd2luZyBjb25kaXRpb25zIGFyZSBtZXQ6XG4gKlxuICogUmVkaXN0cmlidXRpb25zIG9mIHNvdXJjZSBjb2RlIG11c3QgcmV0YWluIHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlLFxuICogdGhpcyBsaXN0IG9mIGNvbmRpdGlvbnMgYW5kIHRoZSBmb2xsb3dpbmcgZGlzY2xhaW1lci5cbiAqXG4gKiBSZWRpc3RyaWJ1dGlvbnMgaW4gYmluYXJ5IGZvcm0gbXVzdCByZXByb2R1Y2UgdGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UsXG4gKiB0aGlzIGxpc3Qgb2YgY29uZGl0aW9ucyBhbmQgdGhlIGZvbGxvd2luZyBkaXNjbGFpbWVyIGluIHRoZSBkb2N1bWVudGF0aW9uXG4gKiBhbmQvb3Igb3RoZXIgbWF0ZXJpYWxzIHByb3ZpZGVkIHdpdGggdGhlIGRpc3RyaWJ1dGlvbi5cbiAqXG4gKiBOZWl0aGVyIHRoZSBuYW1lIG9mIHRoZSBjb3B5cmlnaHQgaG9sZGVyIG5vciB0aGUgbmFtZXMgb2YgaXRzIGNvbnRyaWJ1dG9yc1xuICogbWF5IGJlIHVzZWQgdG8gZW5kb3JzZSBvciBwcm9tb3RlIHByb2R1Y3RzIGRlcml2ZWQgZnJvbSB0aGlzIHNvZnR3YXJlIHdpdGhvdXRcbiAqIHNwZWNpZmljIHByaW9yIHdyaXR0ZW4gcGVybWlzc2lvbi5cbiAqXG4gKiBUSElTIFNPRlRXQVJFIElTIFBST1ZJREVEIEJZIFRIRSBDT1BZUklHSFQgSE9MREVSIEFORCBDT05UUklCVVRPUlMgXCJBUyBJU1wiXG4gKiBBTkQgQU5ZIEVYUFJFU1MgT1IgSU1QTElFRCBXQVJSQU5USUVTLCBJTkNMVURJTkcsIEJVVCBOT1QgTElNSVRFRCBUTywgVEhFXG4gKiBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZIEFORCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRVxuICogQVJFIERJU0NMQUlNRUQuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBDT1BZUklHSFQgT1dORVIgT1IgQ09OVFJJQlVUT1JTIEJFXG4gKiBMSUFCTEUgRk9SIEFOWSBESVJFQ1QsIElORElSRUNULCBJTkNJREVOVEFMLCBTUEVDSUFMLCBFWEVNUExBUlksIE9SXG4gKiBDT05TRVFVRU5USUFMIERBTUFHRVMgKElOQ0xVRElORywgQlVUIE5PVCBMSU1JVEVEIFRPLCBQUk9DVVJFTUVOVCBPRlxuICogU1VCU1RJVFVURSBHT09EUyBPUiBTRVJWSUNFUzsgTE9TUyBPRiBVU0UsIERBVEEsIE9SIFBST0ZJVFM7IE9SIEJVU0lORVNTXG4gKiBJTlRFUlJVUFRJT04pIEhPV0VWRVIgQ0FVU0VEIEFORCBPTiBBTlkgVEhFT1JZIE9GIExJQUJJTElUWSwgV0hFVEhFUiBJTlxuICogQ09OVFJBQ1QsIFNUUklDVCBMSUFCSUxJVFksIE9SIFRPUlQgKElOQ0xVRElORyBORUdMSUdFTkNFIE9SIE9USEVSV0lTRSlcbiAqIEFSSVNJTkcgSU4gQU5ZIFdBWSBPVVQgT0YgVEhFIFVTRSBPRiBUSElTIFNPRlRXQVJFLCBFVkVOIElGIEFEVklTRUQgT0YgVEhFXG4gKiBQT1NTSUJJTElUWSBPRiBTVUNIIERBTUFHRS5cbiAqXG4gKiBHZW5lcmFsIGluZm9ybWF0aW9uXG4gKiBTYWxzYTIwIGlzIGEgc3RyZWFtIGNpcGhlciBzdWJtaXR0ZWQgdG8gZVNUUkVBTSBieSBEYW5pZWwgSi4gQmVybnN0ZWluLlxuICogSXQgaXMgYnVpbHQgb24gYSBwc2V1ZG9yYW5kb20gZnVuY3Rpb24gYmFzZWQgb24gYWRkLXJvdGF0ZS14b3IgKEFSWCkgb3BlcmF0aW9ucyDigJQgMzItYml0IGFkZGl0aW9uLFxuICogYml0d2lzZSBhZGRpdGlvbiAoWE9SKSBhbmQgcm90YXRpb24gb3BlcmF0aW9ucy4gU2Fsc2EyMCBtYXBzIGEgMjU2LWJpdCBrZXksIGEgNjQtYml0IG5vbmNlLFxuICogYW5kIGEgNjQtYml0IHN0cmVhbSBwb3NpdGlvbiB0byBhIDUxMi1iaXQgYmxvY2sgb2YgdGhlIGtleSBzdHJlYW0gKGEgdmVyc2lvbiB3aXRoIGEgMTI4LWJpdCBrZXkgYWxzbyBleGlzdHMpLlxuICogVGhpcyBnaXZlcyBTYWxzYTIwIHRoZSB1bnVzdWFsIGFkdmFudGFnZSB0aGF0IHRoZSB1c2VyIGNhbiBlZmZpY2llbnRseSBzZWVrIHRvIGFueSBwb3NpdGlvbiBpbiB0aGUga2V5XG4gKiBzdHJlYW0gaW4gY29uc3RhbnQgdGltZS4gSXQgb2ZmZXJzIHNwZWVkcyBvZiBhcm91bmQgNOKAkzE0IGN5Y2xlcyBwZXIgYnl0ZSBpbiBzb2Z0d2FyZSBvbiBtb2Rlcm4geDg2IHByb2Nlc3NvcnMsXG4gKiBhbmQgcmVhc29uYWJsZSBoYXJkd2FyZSBwZXJmb3JtYW5jZS4gSXQgaXMgbm90IHBhdGVudGVkLCBhbmQgQmVybnN0ZWluIGhhcyB3cml0dGVuIHNldmVyYWxcbiAqIHB1YmxpYyBkb21haW4gaW1wbGVtZW50YXRpb25zIG9wdGltaXplZCBmb3IgY29tbW9uIGFyY2hpdGVjdHVyZXMuXG4gKi9cblxuY2xhc3MgSlNTYWxzYTIwIHtcblxuICAvKipcbiAgICogQ29uc3RydWN0IFNhbFNhMjAgaW5zdGFuY2Ugd2l0aCBrZXkgYW5kIG5vbmNlXG4gICAqIEtleSBzaG91bGQgYmUgVWludDhBcnJheSB3aXRoIDMyIGJ5dGVzXG4gICAqIE5vbmUgc2hvdWxkIGJlIFVpbnQ4QXJyYXkgd2l0aCA4IGJ5dGVzXG4gICAqXG4gICAqXG4gICAqIEB0aHJvd3Mge0Vycm9yfVxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IGtleVxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IG5vbmNlXG4gICAqL1xuICBjb25zdHJ1Y3RvcihrZXksIG5vbmNlKSB7XG4gICAgaWYgKCEoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkgfHwga2V5Lmxlbmd0aCAhPT0gMzIpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIktleSBzaG91bGQgYmUgMzIgYnl0ZSBhcnJheSFcIik7XG4gICAgfVxuXG4gICAgaWYgKCEobm9uY2UgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB8fCBub25jZS5sZW5ndGggIT09IDgpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIk5vbmNlIHNob3VsZCBiZSA4IGJ5dGUgYXJyYXkhXCIpO1xuICAgIH1cblxuICAgIHRoaXMucm91bmRzID0gMjA7XG4gICAgdGhpcy5zaWdtYSA9IFsweDYxNzA3ODY1LCAweDMzMjA2NDZlLCAweDc5NjIyZDMyLCAweDZiMjA2NTc0XTtcblxuICAgIHRoaXMucGFyYW0gPSBbMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMF07XG5cbiAgICAvLyBzZXQgc2lnbWEgY29uc3RhbnQgLy9cbiAgICB0aGlzLnBhcmFtWzBdID0gdGhpcy5zaWdtYVswXTtcbiAgICB0aGlzLnBhcmFtWzVdID0gdGhpcy5zaWdtYVsxXTtcbiAgICB0aGlzLnBhcmFtWzEwXSA9IHRoaXMuc2lnbWFbMl07XG4gICAgdGhpcy5wYXJhbVsxNV0gPSB0aGlzLnNpZ21hWzNdO1xuXG4gICAgLy8gc2V0IGtleSAvL1xuICAgIHRoaXMucGFyYW1bMV0gPSB0aGlzLl9nZXQzMihrZXksIDApO1xuICAgIHRoaXMucGFyYW1bMl0gPSB0aGlzLl9nZXQzMihrZXksIDQpO1xuICAgIHRoaXMucGFyYW1bM10gPSB0aGlzLl9nZXQzMihrZXksIDgpO1xuICAgIHRoaXMucGFyYW1bNF0gPSB0aGlzLl9nZXQzMihrZXksIDEyKTtcblxuICAgIC8vIHNldCBub25jZSAvL1xuICAgIHRoaXMucGFyYW1bNl0gPSB0aGlzLl9nZXQzMihub25jZSwgMCk7XG4gICAgdGhpcy5wYXJhbVs3XSA9IHRoaXMuX2dldDMyKG5vbmNlLCA0KTtcblxuICAgIC8vIHNldCBjb3VudGVyIC8vXG4gICAgdGhpcy5wYXJhbVs4XSA9IDA7XG4gICAgdGhpcy5wYXJhbVs5XSA9IDA7XG5cbiAgICAvLyBzZXQga2V5IGFnYWluIC8vXG4gICAgdGhpcy5wYXJhbVsxMV0gPSB0aGlzLl9nZXQzMihrZXksIDE2KTtcbiAgICB0aGlzLnBhcmFtWzEyXSA9IHRoaXMuX2dldDMyKGtleSwgMjApO1xuICAgIHRoaXMucGFyYW1bMTNdID0gdGhpcy5fZ2V0MzIoa2V5LCAyNCk7XG4gICAgdGhpcy5wYXJhbVsxNF0gPSB0aGlzLl9nZXQzMihrZXksIDI4KTtcblxuICAgIC8vIGxvZyBwYXJhbVxuICAgIC8vIHRoaXMuX2xvZyh0aGlzLnBhcmFtLCBcInBhcmFtXCIpO1xuXG4gICAgLy8gaW5pdCBibG9jayAvL1xuICAgIHRoaXMuYmxvY2sgPSBbXG4gICAgICAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLFxuICAgICAgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCxcbiAgICBdO1xuXG4gICAgLy8gaW50ZXJuYWwgYnl0ZSBjb3VudGVyIC8vXG4gICAgdGhpcy5ieXRlQ291bnRlciA9IDA7XG4gIH1cblxuICAvKipcbiAgICogIEVuY3J5cHQgb3IgRGVjcnlwdCBkYXRhIHdpdGgga2V5IGFuZCBub25jZVxuICAgKlxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IGRhdGFcbiAgICogQHJldHVybiB7VWludDhBcnJheX1cbiAgICogQHByaXZhdGVcbiAgICovXG4gIF91cGRhdGUoZGF0YSkge1xuXG4gICAgaWYgKCEoZGF0YSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHx8IGRhdGEubGVuZ3RoID09PSAwKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJEYXRhIHNob3VsZCBiZSB0eXBlIG9mIGJ5dGVzIChVaW50OEFycmF5KSBhbmQgbm90IGVtcHR5IVwiKTtcbiAgICB9XG5cbiAgICBjb25zdCBvdXRwdXQgPSBuZXcgVWludDhBcnJheShkYXRhLmxlbmd0aCk7XG5cbiAgICAvLyBjb3JlIGZ1bmN0aW9uLCBidWlsZCBibG9jayBhbmQgeG9yIHdpdGggaW5wdXQgZGF0YSAvL1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgZGF0YS5sZW5ndGg7IGkrKykge1xuICAgICAgaWYgKHRoaXMuYnl0ZUNvdW50ZXIgPT09IDAgfHwgdGhpcy5ieXRlQ291bnRlciA9PT0gNjQpIHtcbiAgICAgICAgdGhpcy5fc2Fsc2EoKTtcbiAgICAgICAgdGhpcy5fY291bnRlckluY3JlbWVudCgpO1xuICAgICAgICB0aGlzLmJ5dGVDb3VudGVyID0gMDtcbiAgICAgIH1cblxuICAgICAgb3V0cHV0W2ldID0gZGF0YVtpXSBeIHRoaXMuYmxvY2tbdGhpcy5ieXRlQ291bnRlcisrXTtcbiAgICB9XG5cbiAgICByZXR1cm4gb3V0cHV0O1xuICB9XG5cbiAgLyoqXG4gICAqICBFbmNyeXB0IGRhdGEgd2l0aCBrZXkgYW5kIG5vbmNlXG4gICAqXG4gICAqIEBwYXJhbSB7VWludDhBcnJheX0gZGF0YVxuICAgKiBAcmV0dXJuIHtVaW50OEFycmF5fVxuICAgKi9cbiAgZW5jcnlwdChkYXRhKSB7XG4gICAgcmV0dXJuIHRoaXMuX3VwZGF0ZShkYXRhKTtcbiAgfVxuXG4gIC8qKlxuICAgKiAgRGVjcnlwdCBkYXRhIHdpdGgga2V5IGFuZCBub25jZVxuICAgKlxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IGRhdGFcbiAgICogQHJldHVybiB7VWludDhBcnJheX1cbiAgICovXG4gIGRlY3J5cHQoZGF0YSkge1xuICAgIHJldHVybiB0aGlzLl91cGRhdGUoZGF0YSk7XG4gIH1cblxuICBfY291bnRlckluY3JlbWVudCgpIHtcbiAgICAvLyBNYXggcG9zc2libGUgYmxvY2tzIGlzIDJeNjRcbiAgICB0aGlzLnBhcmFtWzhdID0gKHRoaXMucGFyYW1bOF0gKyAxKSA+Pj4gMDtcbiAgICBpZiAodGhpcy5wYXJhbVs4XSA9PSAwKSB7XG4gICAgICB0aGlzLnBhcmFtWzldID0gKHRoaXMucGFyYW1bOV0gKyAxKSA+Pj4gMDtcbiAgICB9XG4gIH1cblxuICBfc2Fsc2EoKSB7XG4gICAgY29uc3QgbWl4ID0gWzAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDBdO1xuICAgIGxldCBpID0gMCwgYiA9IDA7XG5cbiAgICAvLyBjb3B5IHBhcmFtIGFycmF5IHRvIG1peCAvL1xuICAgIGZvciAoaSA9IDA7IGkgPCAxNjsgaSsrKSB7XG4gICAgICBtaXhbaV0gPSB0aGlzLnBhcmFtW2ldO1xuICAgIH1cblxuICAgIC8vIG1peCByb3VuZHMgLy9cbiAgICBmb3IgKGkgPSAwOyBpIDwgdGhpcy5yb3VuZHM7IGkgKz0gMikge1xuICAgICAgdGhpcy5fcXVhcnRlcihtaXgsIDQsIDgsIDEyLCAwKTtcbiAgICAgIHRoaXMuX3F1YXJ0ZXIobWl4LCA5LCAxMywgMSwgNSk7XG4gICAgICB0aGlzLl9xdWFydGVyKG1peCwgMTQsIDIsIDYsIDEwKTtcbiAgICAgIHRoaXMuX3F1YXJ0ZXIobWl4LCAzLCA3LCAxMSwgMTUpO1xuICAgICAgdGhpcy5fcXVhcnRlcihtaXgsIDEsIDIsIDMsIDApO1xuICAgICAgdGhpcy5fcXVhcnRlcihtaXgsIDYsIDcsIDQsIDUpO1xuICAgICAgdGhpcy5fcXVhcnRlcihtaXgsIDExLCA4LCA5LCAxMCk7XG4gICAgICB0aGlzLl9xdWFydGVyKG1peCwgMTIsIDEzLCAxNCwgMTUpO1xuICAgIH1cblxuICAgIGZvciAoaSA9IDA7IGkgPCAxNjsgaSsrKSB7XG4gICAgICAvLyBhZGRcbiAgICAgIG1peFtpXSArPSB0aGlzLnBhcmFtW2ldO1xuXG4gICAgICAvLyBzdG9yZVxuICAgICAgdGhpcy5ibG9ja1tiKytdID0gbWl4W2ldICYgMHhGRjtcbiAgICAgIHRoaXMuYmxvY2tbYisrXSA9IChtaXhbaV0gPj4+IDgpICYgMHhGRjtcbiAgICAgIHRoaXMuYmxvY2tbYisrXSA9IChtaXhbaV0gPj4+IDE2KSAmIDB4RkY7XG4gICAgICB0aGlzLmJsb2NrW2IrK10gPSAobWl4W2ldID4+PiAyNCkgJiAweEZGO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBTYWxzYSBxdWFydGVyIGZ1bmN0aW9uXG4gICAqXG4gICAqIEBwYXJhbSB7W251bWJlcl19IGRhdGFcbiAgICogQHBhcmFtIHtudW1iZXJ9IGFcbiAgICogQHBhcmFtIHtudW1iZXJ9IGJcbiAgICogQHBhcmFtIHtudW1iZXJ9IGNcbiAgICogQHBhcmFtIHtudW1iZXJ9IGRcbiAgICogQHByaXZhdGVcbiAgICovXG4gIF9xdWFydGVyKGRhdGEsIGEsIGIsIGMsIGQpIHtcbiAgICAvLyA+Pj4gMCBjb252ZXJ0IGRvdWJsZSB0byB1bnNpZ25lZCBpbnRlZ2VyIDMyIGJpdFxuICAgIGRhdGFbYV0gPSAoZGF0YVthXSBeIHRoaXMuX3JvdGwoZGF0YVtkXSArIGRhdGFbY10sIDcpKSA+Pj4gMDtcbiAgICBkYXRhW2JdID0gKGRhdGFbYl0gXiB0aGlzLl9yb3RsKGRhdGFbYV0gKyBkYXRhW2RdLCA5KSkgPj4+IDA7XG4gICAgZGF0YVtjXSA9IChkYXRhW2NdIF4gdGhpcy5fcm90bChkYXRhW2JdICsgZGF0YVthXSwgMTMpKSA+Pj4gMDtcbiAgICBkYXRhW2RdID0gKGRhdGFbZF0gXiB0aGlzLl9yb3RsKGRhdGFbY10gKyBkYXRhW2JdLCAxOCkpID4+PiAwO1xuICB9XG5cbiAgLyoqXG4gICAqIExpdHRsZS1lbmRpYW4gdG8gdWludCAzMiBieXRlc1xuICAgKlxuICAgKiBAcGFyYW0ge1VpbnQ4QXJyYXl8W251bWJlcl19IGRhdGFcbiAgICogQHBhcmFtIHtudW1iZXJ9IGluZGV4XG4gICAqIEByZXR1cm4ge251bWJlcn1cbiAgICogQHByaXZhdGVcbiAgICovXG4gIF9nZXQzMihkYXRhLCBpbmRleCkge1xuICAgIHJldHVybiBkYXRhW2luZGV4KytdIF4gKGRhdGFbaW5kZXgrK10gPDwgOCkgXiAoZGF0YVtpbmRleCsrXSA8PCAxNikgXiAoZGF0YVtpbmRleF0gPDwgMjQpO1xuICB9XG5cbiAgLyoqXG4gICAqIEN5Y2xpYyBsZWZ0IHJvdGF0aW9uXG4gICAqXG4gICAqIEBwYXJhbSB7bnVtYmVyfSBkYXRhXG4gICAqIEBwYXJhbSB7bnVtYmVyfSBzaGlmdFxuICAgKiBAcmV0dXJuIHtudW1iZXJ9XG4gICAqIEBwcml2YXRlXG4gICAqL1xuICBfcm90bChkYXRhLCBzaGlmdCkge1xuICAgIHJldHVybiAoKGRhdGEgPDwgc2hpZnQpIHwgKGRhdGEgPj4+ICgzMiAtIHNoaWZ0KSkpO1xuICB9XG59XG5cbi8vIEVYUE9SVCAvL1xuaWYgKHR5cGVvZiBtb2R1bGUgIT09IFwidW5kZWZpbmVkXCIgJiYgbW9kdWxlLmV4cG9ydHMpIHtcbiAgbW9kdWxlLmV4cG9ydHMgPSBKU1NhbHNhMjA7XG59XG4iXX0=