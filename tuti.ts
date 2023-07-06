import { SigHashType,Utils,hash160,checkSig,Tx,Pubkey,Sig,SigHash,SigHashPreimage ,PubKeyHash,assert, ByteString, hash256, method, prop, SmartContract } from 'scrypt-ts'


// miner fee in satoshi per each withdraw    
// miner fee in satoshi per each withdraw    
export const withdrawMinerFee = 6000n;

export class Payment extends SmartContract{

    @prop()
    // withdraw interval limit in seconds
    withdrawIntervals: bigint;
    @prop()
    // how many satoshis can be withdrawn each time
    withdrawAmount: bigint;
    // public key hash of the creator, the creator is student
    @prop()
    creatorPkh: PubKeyHash;
    @prop(true)
    lastWithdrawTimestamp: bigint;


    constructor(withdrawIntervals: bigint, withdrawAmount: bigint,creatorPkh: PubKeyHash, lastWithdrawTimestamp: bigint) {
        super(...arguments);
        this.withdrawIntervals = withdrawIntervals;
        this.withdrawAmount = withdrawAmount;
        this.creatorPkh = creatorPkh;
        this.lastWithdrawTimestamp = lastWithdrawTimestamp;
    }



    @method()
    //the pkh will be the univesity's pubkeyhash
    public withdraw(pkh: PubKeyHash) {
        assert(this.ctx.sequence < 0xffffffff);
        // require meets the call interval limits
        assert(this.ctx.locktime - this.lastWithdrawTimestamp >= this.withdrawIntervals);
        assert(this.ctx.locktime - this.lastWithdrawTimestamp < 2n * this.withdrawIntervals);

        this.lastWithdrawTimestamp = this.ctx.locktime;
        let contractOutput: ByteString = Utils.buildOutput(this.getStateScript(), this.ctx.utxo.value - this.withdrawAmount - withdrawMinerFee);
        let withdrawOutput: ByteString = Utils.buildOutput(Utils.buildPublicKeyHashScript(pkh), this.withdrawAmount);
        // require 3 outputs
        let expectedOutputs: ByteString = contractOutput + withdrawOutput;
        expectedOutputs += this.buildChangeOutput();
        assert(this.ctx.hashOutputs == hash256(expectedOutputs), 'Hash output dismatch');
    }
    @method()
    public deposit(depositAmount: number,sig: Sig, pk: PubKey) {
       // only the creator can deposit
       assert(hash160(pk) == this.creatorPkh);
       assert(this.checkSig(sig, pk));
       // avoid stealing money from the contract
       assert(depositAmount > 0);
       let expectedOutput: ByteString = Utils.buildOutput(this.getStateScript(), this.ctx.utxo.value + BigInt(depositAmount));
       assert(this.ctx.hashOutputs == hash256(expectedOutput), 'Hash output dismatch');
   }

    @method()
    public destroy(sig: Sig, pk: PubKey) {
        // only the creator can destroy
        assert(hash160(pk) == this.creatorPkh);
        assert(this.checkSig(sig, pk));
    }


}