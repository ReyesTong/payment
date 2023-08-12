import { type } from 'os';
import {
    SmartContract,
    prop,
    ByteString,
    method,
    assert,
    Utils,
    Sig,
    PubKey,
    hash256,
    hash160,
} from 'scrypt-ts'
import { RabinSig, RabinPubKey, RabinVerifierWOC } from 'scrypt-ts-lib'

export type OracleData = {
    GPA: bigint
    PK : PubKey 
}

export class Scholarship extends SmartContract{
    //GPA target
    @prop()
    targetGPA: bigint;
    // Oracles Rabin pubulic key
    @prop()
    oraclePubKey: RabinPubKey;
    @prop()
    scolarshipAmout: bigint;
    //Univerity's public key
    @prop()
    universityPubKey: PubKey;

    constructor(targetGPA: bigint, oraclePubKey: RabinPubKey,scolarshipAmout: bigint, universityPubKey: PubKey){
        super(...arguments);
        this.targetGPA = targetGPA;
        this.oraclePubKey = oraclePubKey;
        this.scolarshipAmout = scolarshipAmout;
        this.universityPubKey = universityPubKey;
    }


    @method()
    static parseData(GPAmsg: ByteString,PKmsg: ByteString): OracleData {
        return {
            GPA: Utils.fromLEUnsigned(GPAmsg),
            PK : PubKey(PKmsg)
        }
    }

    @method()
    public unlock(GPAmsg: ByteString, PKmsg: ByteString,GPAsig: RabinSig, PKsig: RabinSig){
        assert(
            RabinVerifierWOC.verifySig(GPAmsg, GPAsig, this.oraclePubKey),
            "Oracle sig verify failed!"
        );
        assert(
            RabinVerifierWOC.verifySig(PKmsg, PKsig, this.oraclePubKey),
            "Oracle sig verify failed!"
        );

        const oracleData = Scholarship.parseData(GPAmsg,PKmsg);


        assert(oracleData.GPA >= this.targetGPA, "GPA is not good enough!")

        //I am not sure those code is necessary
        const contractOutput: ByteString = this.buildStateOutput(this.ctx.utxo.value - this.scolarshipAmout)
        const GPAOutput: ByteString = Utils.buildPublicKeyHashOutput(hash160(oracleData.PK), oracleData.GPA)
        const expectedOutputs: ByteString = contractOutput + GPAOutput + this.buildChangeOutput();
        assert(this.ctx.hashOutputs == hash256(expectedOutputs), 'hashOutputs dismatch');
    }

    @method()
    public deposit(depositAmount: bigint, sig: Sig) {
    // only the student can deposit
       assert(this.checkSig(sig, this.universityPubKey), 'checkSig failed');
    // avoid stealing money from the contract
       assert(depositAmount > 0, 'deposit amount should be positive');

       const contractOutput: ByteString = this.buildStateOutput(this.ctx.utxo.value + depositAmount)
       const expectedOutputs: ByteString = contractOutput + this.buildChangeOutput()
       assert(this.ctx.hashOutputs == hash256(expectedOutputs), 'hashOutputs dismatch');
   }

    @method()
    public destroy(sig: Sig) {
    // only the university can destroy
       assert(this.checkSig(sig, this.universityPubKey), 'checkSig failed');
   }


}