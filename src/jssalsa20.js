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
   *
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
    this.param[8] = 7;
    this.param[9] = 0;

    // set key again //
    this.param[11] = this._get32(key, 16);
    this.param[12] = this._get32(key, 20);
    this.param[13] = this._get32(key, 24);
    this.param[14] = this._get32(key, 28);

    // init block //
    this.block = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // generate first block //

  }

  /**
   *
   * @param {Uint8Array} data
   * @return {Uint8Array}
   */
  update(data) {

    if (!(data instanceof Uint8Array) || data.length === 0) {
      throw new Error("Data should be type of Uint8Array and not empty!");
    }

    const output = new Array(data.length);

    // init output array //
    for (let i = 0; i < data.length; i++) {
      output[i] = 0;
    }

    this._salsa();

    return new Uint8Array([0]);
  }

  _generateBlock() {

  }

  _counterIncrement() {
    // Max possible blocks is 2^64

    this.param[8] = (this.param[8] + 1) & 0x7FFFFFFF;
    if (this.param[8] == 0) {
      this.param[9] = (this.param[9] + 1) & 0x7FFFFFFF;
    }
  }

  _salsa() {
    const mix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let i = 0, b = 0, u;

    // copy param array to mix //
    for (i = 0; i < 16; i++) {
      mix[i] = this.param[i];
    }

    let x4 = mix[4];

    // mix rounds //
    for (i = 0; i < this.rounds; i += 2) {

      // u = mix[0] + mix[12];
      // x4 = (x4 ^ (u << 7) | (u >> (32 - 7))) & 0xFFFFFFFF;
      // mix[4] ^= ((u << 7) | (u >>> (32 - 7))) & 0x0FFFFFFFF;

      this._quarterround(mix, 4, 0, 12, 7);
      this._quarterround(mix, 8, 4, 0, 9);
      this._quarterround(mix, 12, 8, 4, 13);
      this._quarterround(mix, 0, 12, 8, 18);

      this._quarterround(mix, 9, 5, 1, 7);
      this._quarterround(mix, 13, 9, 5, 9);
      this._quarterround(mix, 1, 13, 9, 13);
      this._quarterround(mix, 5, 1, 13, 18);

      this._quarterround(mix, 14, 10, 6, 7);
      this._quarterround(mix, 2, 14, 10, 9);
      this._quarterround(mix, 6, 2, 14, 13);
      this._quarterround(mix, 10, 6, 2, 18);

      this._quarterround(mix, 3, 15, 11, 7);
      this._quarterround(mix, 7, 3, 15, 9);
      this._quarterround(mix, 11, 7, 3, 13);
      this._quarterround(mix, 15, 11, 7, 18);

      this._quarterround(mix, 1, 0, 3, 7);
      this._quarterround(mix, 2, 1, 0, 9);
      this._quarterround(mix, 3, 2, 1, 13);
      this._quarterround(mix, 0, 3, 2, 18);

      this._quarterround(mix, 6, 5, 4, 7);
      this._quarterround(mix, 7, 6, 5, 9);
      this._quarterround(mix, 4, 7, 6, 13);
      this._quarterround(mix, 5, 4, 7, 18);

      this._quarterround(mix, 11, 10, 9, 7);
      this._quarterround(mix, 8, 11, 10, 9);
      this._quarterround(mix, 9, 8, 11, 13);
      this._quarterround(mix, 10, 9, 9, 18);

      this._quarterround(mix, 12, 15, 14, 7);
      this._quarterround(mix, 13, 12, 15, 9);
      this._quarterround(mix, 14, 13, 12, 13);
      this._quarterround(mix, 15, 14, 13, 18);

      continue;
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
  }

  /**
   *
   * @param {[number]} data
   * @param {number} a
   * @param {number} b
   * @param {number} c
   * @param {number} d
   * @private
   */
  _quarterround(data, a, b, c, shift) {
    data[a] = data[a] ^ this._rotl(data[b] + data[c], shift);
  }

  /**
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
    return (((data << shift) | (data >> (32 - shift))) + 0x100000000) & 0xFFFFFFFF;
  }
}

const key = new Uint8Array([
  1, 2, 3, 4, 5, 6, 7, 8,
  9, 10, 11, 12, 13, 14, 15,
  16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, 26, 27, 28, 29, 30, 21, 21
]);

const nonce = new Uint8Array([3, 1, 4, 1, 5, 9, 2, 6]);

const salsa = new JSSalsa20(key, nonce);

console.log(salsa.update(new Uint8Array([0x01, 0x01, 0x01, 0x01])));

// EXPORT //
if (typeof module !== "undefined" && module.exports) {
  module.exports = JSSalsa20;
}
