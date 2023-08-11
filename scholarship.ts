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
    slice,
    hash256,
    hash160,
    toByteString
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
    //Student's public key
    @prop()
    studentPubKey: PubKey;
    //Univerity's public key
    @prop()
    universityPubKey: PubKey;

    constructor(targetGPA: bigint, oraclePubKey: RabinPubKey, studentPubKey: PubKey, universityPubKey: PubKey){
        super(...arguments);
        this.targetGPA = targetGPA;
        this.oraclePubKey = oraclePubKey;
        this.studentPubKey = studentPubKey;
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


        assert(oracleData.PK == this.studentPubKey, "Error: PubKey dismatch!")
        assert(oracleData.GPA >= this.targetGPA, "GPA is not good enough!")

        //I am not sure those code is necessary
        const GPAOutput: ByteString = Utils.buildPublicKeyHashOutput(hash160(this.studentPubKey), oracleData.GPA)
        const expectedOutputs: ByteString = GPAOutput + this.buildChangeOutput() + this.buildChangeOutput();
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
    // only the student can destroy
       assert(this.checkSig(sig, this.universityPubKey), 'checkSig failed');
   }


}