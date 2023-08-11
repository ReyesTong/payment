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
    hash160
} from 'scrypt-ts'
import { RabinSig, RabinPubKey, RabinVerifierWOC } from 'scrypt-ts-lib'

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
    static parseGPA(GPAmsg: ByteString): bigint {
        return Utils.fromLEUnsigned(GPAmsg);
    }

    @method()
    static parsePK(PKmsg: ByteString): PubKey {
        return Utils.fromLEUnsigned(PKmsg);
    }

    @method()
    public unlock(GPAmsg: ByteString, PKmsg: ByteString,sig: RabinSig){
        assert(
            RabinVerifierWOC.verifySig(GPAmsg, sig, this.oraclePubKey),
            "Oracle sig verify failed!"
        );
        assert(
            RabinVerifierWOC.verifySig(PKmsg, sig, this.oraclePubKey),
            "Oracle sig verify failed!"
        );

        const studentGPA = Scholarship.parseGPA(GPAmsg);
        const studentPK = Scholarship.parsePK(PKmsg);

        assert(studentPK == this.studentPubKey, "Error: PubKey Mismatching!")
        assert(studentGPA >= this.targetGPA, "GPA is not good enough!")

        //I am not sure those code is necessary
        const GPAOutput: ByteString = Utils.buildPublicKeyHashOutput(hash160(this.studentPubKey), studentGPA)
        const expectedOutputs: ByteString = GPAOutput + this.buildChangeOutput();
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