import { test } from '@substrate-system/tapzero'
import { CryptographyKey, SodiumPlus } from 'sodium-plus'
import { encryptData, decryptData, deriveKeys } from '../src/symmetric'

let sodium

test('Symmetric Functions -- Key derivation', async t => {
    if (!sodium) sodium = await SodiumPlus.auto()
    const testInput = new CryptographyKey(await sodium.crypto_generichash('Dhole fursonas rule <3'))
    const { encKey, commitment } = await deriveKeys(testInput, Buffer.alloc(24))
    const test1: string = await sodium.sodium_bin2hex(encKey.getBuffer())
    const test2: string = await sodium.sodium_bin2hex(commitment)
    t.ok(!(test1 === test2), 'should return different outputs')

    // Test vectors for key derivation:
    t.equal(test1, '3b368faa76856300d81db67f3578ecfa5e00e331b42749bf07da63f11da8f12b')
    t.equal(test2, '03cf2a39983ae6da8046bc7ee0091827bd2c3c7eda475660b04cbff30bf8a94b')
})

test('Symmetric Encryption / Decryption', async t => {
    if (!sodium) sodium = await SodiumPlus.auto()
    const key = await sodium.crypto_secretbox_keygen()

    const plaintext = "Rawr x3 nuzzles how are you *pounces on you* you're so warm o3o *notices you have a bulge*"
    const encrypted = await encryptData(plaintext, key)
    t.ok(!(encrypted === plaintext), 'Encrypted text should not equal plaintext')
    t.equal(encrypted[0], 'v', 'First letter should be "v')
    const decrypted = await decryptData(encrypted, key)
    t.equal(decrypted.toString(), plaintext, 'should be able to decrypt the text')
})
