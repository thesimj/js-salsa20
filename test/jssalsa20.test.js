'use strict'
/**
 * Created by Mykola Bubelich
 * 2017-01-25
 */

import test from 'tape'
import JSSalsa20 from '../src/jssalsa20'

/**
 * General Test
 */
test("Class 'JSSalsa20' should exists", tape => {
  const salsa = new JSSalsa20(new Uint8Array(32), new Uint8Array(8))
  tape.assert(salsa instanceof JSSalsa20)

  tape.end()
})

test("Function 'encrypt' should exists", tape => {
  const salsa = new JSSalsa20(new Uint8Array(32), new Uint8Array(8))
  tape.assert(typeof salsa.encrypt === 'function')

  tape.end()
})

test("Function 'decrypt' should exists", tape => {
  const salsa = new JSSalsa20(new Uint8Array(32), new Uint8Array(8))
  tape.assert(typeof salsa.decrypt === 'function')

  tape.end()
})

/**
 * Errors handlers
 */
test('When set key with length not 32 byte, error should be thrown', tape => {
  tape.throws(() => {
    new JSSalsa20(null, null)
  }, /Key should be 32 byte array!/)

  tape.end()
})

test('When set nonce with length not 8 byte, error should be thrown', tape => {
  tape.throws(() => {
    new JSSalsa20(new Uint8Array(32), null)
  }, /Nonce should be 8 byte array!/)

  tape.end()
})

test('When not bytes pass to encryt/decrypt method, error should be thrown', tape => {
  tape.throws(() => {
    new JSSalsa20(new Uint8Array(32), new Uint8Array(8)).encrypt(null)
  }, /Data should be type of bytes \(Uint8Array\) and not empty!/)

  tape.end()
})

/**
 * Encrypt / Decrypt
 */
test('Encrypt and decrypt for 256 byte should be same', tape => {
  const crypto = require('crypto')

  const key = new Uint8Array(crypto.randomBytes(32))
  const nonce = new Uint8Array(crypto.randomBytes(8))
  const data = new Uint8Array(crypto.randomBytes(4096))

  const encoder = new JSSalsa20(key, nonce)
  const decoder = new JSSalsa20(key, nonce)

  const encr = encoder.encrypt(data)
  const decr = decoder.decrypt(encr)

  tape.deepEqual(encoder.param, decoder.param, 'Parameters should be equivalent')
  tape.deepEqual(data, decr, 'Decrypted data should be the same as input')
  tape.deepEqual([64, 64], [encoder.param[8], decoder.param[8]], 'Counter should be equal 64')

  tape.end()
})

test('First block and param should be equal to reference', tape => {
  const exp_param = [
    0x61707865, 0x04030201, 0x08070605, 0x0c0b0a09,
    0x100f0e0d, 0x3320646e, 0x01040103, 0x06020905,
    0x00000007, 0x00000000, 0x79622d32, 0x14131211,
    0x18171615, 0x1c1b1a19, 0x201f1e1d, 0x6b206574
  ]

  const exp_block = [
    0xa3, 0x05, 0xa2, 0xb9, 0x50, 0xe1, 0x95, 0x06, 0x1a, 0x88, 0x94, 0xaa, 0x2c, 0xb1, 0xb7, 0xad,
    0xd4, 0x42, 0x89, 0x79, 0x16, 0x70, 0x10, 0x26, 0xa4, 0xb1, 0xed, 0x64, 0x3f, 0x17, 0x27, 0x2d,
    0xfa, 0xf1, 0xc7, 0xb1, 0xdc, 0x6e, 0x06, 0x62, 0x23, 0xfa, 0x35, 0xe0, 0x04, 0x6f, 0x49, 0xc4,
    0xb3, 0xe6, 0x31, 0x21, 0x28, 0xde, 0x0b, 0x81, 0x07, 0xb4, 0x2c, 0xf6, 0x3d, 0xde, 0xde, 0x6b
  ]
  const key = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
  ])

  const nonce = new Uint8Array([3, 1, 4, 1, 5, 9, 2, 6])

  const instance = new JSSalsa20(key, nonce)

  // Set block count to 7 //
  instance.param[8] = 7

  tape.deepEqual(instance.param, exp_param, 'Param should be the same as in design')

  instance.encrypt(new Uint8Array(1))

  tape.deepEqual(instance.block, exp_block, 'Block should be the same as in design')

  tape.end()
})

