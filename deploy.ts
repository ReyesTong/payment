import { Payment } from './src/contracts/payment'
import { bsv, TestWallet, DefaultProvider, Ripemd160, PubKey, toHex } from 'scrypt-ts'

import * as dotenv from 'dotenv'

// Load the .env file
dotenv.config()

// Read the private key from the .env file.
// The default private key inside the .env file is meant to be used for the Bitcoin testnet.
// See https://scrypt.io/docs/bitcoin-basics/bsv/#private-keys
const privateKey = bsv.PrivateKey.fromWIF(process.env.PRIVATE_KEY || '')

// Prepare signer.
// See https://scrypt.io/docs/how-to-deploy-and-call-a-contract/#prepare-a-signer-and-provider
const signer = new TestWallet(
    privateKey,
    new DefaultProvider({
        network: bsv.Networks.testnet,
    })
)

async function main() {
    await Payment.compile()

    // TODO: Adjust the amount of satoshis locked in the smart contract:
    const amount = 100
    const withdrawIntervals = 10000n
    const withdrawAmount = 300000n
    const creatorPkh = 'mnai8LzKea5e3C9qgrBo7JHgpiEnHKMhwR'
    const universityPKH = "University's public key hash here"
    const lastWithdrawTimestamp = 222n 
    
    
    const instance = new Payment(
        withdrawIntervals,
        withdrawAmount,
        lastWithdrawTimestamp,
        PubKey(toHex(creatorPkh)),
        PubKey(toHex(universityPKH))
    )

    // Connect to a signer.
    await instance.connect(signer)

    // Contract deployment.
    const deployTx = await instance.deploy(amount)
    console.log(`Payment contract deployed: ${deployTx.id}`)
}

main()
