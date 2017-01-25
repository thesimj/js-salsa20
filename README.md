# JS-Salsa20
Pure JavaScript Salsa20 stream cipher

### Abstract
Salsa20 is a family of 256-bit stream ciphers designed in 2005
and submitted to eSTREAM, the ECRYPT Stream Cipher Project.
Salsa20 has progressed to the third round of eSTREAM without any
changes. The 20-round stream cipher Salsa20/20 is consistently faster
than AES and is recommended by the designer for typical cryptographic
applications.

### Usage
Encrypt message with key and nonce
```javascript
import JSSalsa20 from "js-salsa20";

const key = Uint8Array([...]); // 32 bytes key
const nonce = Uint8Array([...]); // 8 bytes nonce
const message = Uint8Array([...]); // some data as bytes array

// Encrypt //
const encrypt = new JSSalsa20(key, nonce).encrypt(message);

// now encrypt contains bytes array of encrypted message
```

Decrypt encrypted message with key and nonce
```javascript
import JSSalsa20 from "js-salsa20";

const key = Uint8Array([...]); // 32 bytes key
const nonce = Uint8Array([...]); // 8 bytes nonce
const encrypt = Uint8Array([...]); // some data as bytes array

// Encrypt //
const message = new JSSalsa20(key, nonce).decrypt(encrypt);

// now message contains bytes array of original message
```

That all. If something happens, Error will be thrown.
More examples you can find in tests files.
