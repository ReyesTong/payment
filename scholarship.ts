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
    static parseGPA(msg: ByteString): bigint {
        return Utils.fromLEUnsigned(msg);
    }

    @method()
    public unlock(msg: ByteString, sig: RabinSig, studenSig: Sig){
        assert(this.checkSig(studenSig, this.studentPubKey),"ChcekSig Failed!");
        assert(
            RabinVerifierWOC.verifySig(msg, sig, this.oraclePubKey),
            "Oracle sig verify failed!"
        );
        const studentGPA = Scholarship.parseGPA(msg);
        
        assert(studentGPA >= this.targetGPA, "GPA is not good enough!")
        assert(this.checkSig(studenSig, this.studentPubKey))

        //I am not sure those code is necessary
        const GPAOutput: ByteString = Utils.buildPublicKeyHashOutput(hash160(this.studentPubKey), studentGPA)
        const expectedOutputs: ByteString = GPAOutput + this.buildChangeOutput();
        assert(this.ctx.hashOutputs == hash256(expectedOutputs), 'hashOutputs dismatch');
    }


}