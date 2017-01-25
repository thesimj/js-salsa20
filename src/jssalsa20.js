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

class JSSalsa20 {

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
  constructor(key, nonce) {
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
    this.block = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

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
  _update(data) {

    if (!(data instanceof Uint8Array) || data.length === 0) {
      throw new Error("Data should be type of Uint8Array and not empty!");
    }

    const output = new Uint8Array(data.length);

    // core function, build block and xor with input data //
    for (let i = 0; i < data.length; i++) {
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
  encrypt(data) {
    return this._update(data);
  }

  /**
   *  Decrypt data with key and nonce
   *
   * @param {Uint8Array} data
   * @return {Uint8Array}
   */
  decrypt(data) {
    return this._update(data);
  }

  _counterIncrement() {
    // Max possible blocks is 2^64
    this.param[8] = (this.param[8] + 1) >>> 0;
    if (this.param[8] == 0) {
      this.param[9] = (this.param[9] + 1) >>> 0;
    }
  }

  _salsa() {
    const mix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let i = 0, b = 0;

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
      this.block[b++] = (mix[i] >>> 8) & 0xFF;
      this.block[b++] = (mix[i] >>> 16) & 0xFF;
      this.block[b++] = (mix[i] >>> 24) & 0xFF;
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
  _quarter(data, a, b, c, d) {
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
  _get32(data, index) {
    return data[index++] ^ (data[index++] << 8) ^ (data[index++] << 16) ^ (data[index] << 24);
  }

  /**
   * Cyclic left rotation
   *
   * @param {number} data
   * @param {number} shift
   * @return {number}
   * @private
   */
  _rotl(data, shift) {
    return ((data << shift) | (data >>> (32 - shift)));
  }

  /**
   * Helper log function
   *
   * @param {[number]} data
   * @param {String} message
   * @private
   */
  _log(data, message = "") {

    console.log("\n log: " + message);

    for (let i = 0; i < data.length; i += 4) {
      const a = ("0x00000000" + data[i].toString(16)).slice(-8);
      const b = ("0x00000000" + data[i + 1].toString(16)).slice(-8);
      const c = ("0x00000000" + data[i + 2].toString(16)).slice(-8);
      const d = ("0x00000000" + data[i + 3].toString(16)).slice(-8);

      console.log(a, b, c, d);
    }
  }
}

// EXPORT //
if (typeof module !== "undefined" && module.exports) {
  module.exports = JSSalsa20;
}
