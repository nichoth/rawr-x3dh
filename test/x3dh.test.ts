import { test } from '@bicycle-codes/tapzero'
import {
    type InitSenderInfo,
    type PreKeyPair,
    X3DH
} from '../index.js'
import type { Ed25519PublicKey, Ed25519SecretKey } from 'sodium-plus'
import { SodiumPlus } from 'sodium-plus'

test('__X3DH E2E tests__')

const fox_x3dh = new X3DH()
const wolf_x3dh = new X3DH()
let fox_sk:Ed25519SecretKey
let wolf_pre:PreKeyPair
let fox_pk:Ed25519PublicKey
let wolf_pk:Ed25519PublicKey
let wolf_sk:Ed25519SecretKey
let sodium:Awaited<ReturnType<typeof SodiumPlus.auto>>
// let fox_pre:PreKeyPair
test('X3DH Handshake with One-Time Keys', async t => {
    sodium = await SodiumPlus.auto()

    // 1. Generate identity keys
    const fox_keypair = await sodium.crypto_sign_keypair()
    fox_sk = await sodium.crypto_sign_secretkey(fox_keypair)
    fox_pk = await sodium.crypto_sign_publickey(fox_keypair)
    const wolf_keypair = await sodium.crypto_sign_keypair()
    wolf_sk = await sodium.crypto_sign_secretkey(wolf_keypair)
    wolf_pk = await sodium.crypto_sign_publickey(wolf_keypair)

    // 4. Generate some one-time keys
    const fox_bundle = await fox_x3dh.generateOneTimeKeys(fox_sk, 3)
    const wolf_bundle = await wolf_x3dh.generateOneTimeKeys(wolf_sk, 3)

    // 5. Do an initial handshake from fox->wolf
    const message = 'hewwo UwU'
    const sent = await fox_x3dh.initSend('wolf', wolfResponse, message)

    // 6. Pass the handshake to wolf->fox
    const [sender, recv] = await wolf_x3dh.initRecv(sent)
    t.equal(sender, 'fox', 'should have "fox" as sender')
    t.equal(recv.toString(), message, 'should decrypt the message')
})

test('2. Instantiate object with same config (defaults)', async t => {
    await fox_x3dh.identityKeyManager.setIdentityKeypair(fox_sk, fox_pk)
    await fox_x3dh.setIdentityString('fox')
    await wolf_x3dh.identityKeyManager.setIdentityKeypair(wolf_sk, wolf_pk)
    await wolf_x3dh.setIdentityString('wolf')

    t.equal('fox', await fox_x3dh.identityKeyManager.getMyIdentityString(),
        'should return the right identity string')

    t.equal('wolf', await wolf_x3dh.identityKeyManager.getMyIdentityString(),
        "should return wolf's identity string")
})

test('3. Generate a pre-key for each.', async t => {
    // const fox_pre = await fox_x3dh.identityKeyManager.getPreKeypair()
    wolf_pre = await wolf_x3dh.identityKeyManager.getPreKeypair()
    t.ok(wolf_pre, 'should return a pre keypair')
})

test('4. Generate some one-time keys', async t => {
    const fox_bundle = await fox_x3dh.generateOneTimeKeys(fox_sk, 3)
    const wolf_bundle = await wolf_x3dh.generateOneTimeKeys(wolf_sk, 3)

    t.ok(fox_bundle)
    t.ok(wolf_bundle)
})

let sent:InitSenderInfo
let message:string
test('5. Do an initial handshake from fox->wolf', async t => {
    message = 'hewwo UwU'
    sent = await fox_x3dh.initSend('wolf', wolfResponse, message)
    t.ok(sent)
})

test('6. Pass the handshake to wolf->fox', async t => {
    const [sender, recv] = await wolf_x3dh.initRecv(sent)
    t.equal(sender, 'fox', 'sender should be "fox"')
    t.equal(recv.toString(), message, 'should decrypt the message')
})

test('send and recieve a few more', async t => {
    // Send and receive a few more:
    for (let i = 0; i < 20; i++) {
        try {
            const plain = `OwO what's this? ${i}`

            if ((i % 3) === 0) {
                const cipher = await wolf_x3dh.encryptNext('fox', plain)
                const decrypt = await fox_x3dh.decryptNext('wolf', cipher)
                t.equal(decrypt.toString(), plain, 'should decrypt the text')
            } else {
                const cipher = await fox_x3dh.encryptNext('wolf', plain)
                const decrypt = await wolf_x3dh.decryptNext('fox', cipher)
                t.equal(decrypt.toString(), plain, `round ${i + 1} is ok`)
            }
        } catch (e) {
            console.log('Failed at i = ' + i)
            throw e
        }
    }
})

async function wolfResponse () {
    const sig = await signBundle(wolf_sk, [wolf_pre.preKeyPublic]);
    return {
        IdentityKey: await sodium.sodium_bin2hex(wolf_pk.getBuffer()),
        SignedPreKey: {
            Signature: await sodium.sodium_bin2hex(sig),
            PreKey: await sodium.sodium_bin2hex(wolf_pre.preKeyPublic.getBuffer())
        },
        OneTimeKey: wolf_bundle.bundle[0]
    }
}
