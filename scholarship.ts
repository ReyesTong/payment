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

    constructor(targetGPA: bigint, oraclePubKey: RabinPubKey, studentPubKey: PubKey, universityPubKey){
        super(...arguments);
        this.targetGPA = targetGPA;
        this.oraclePubKey = oraclePubKey;
        this.studentPubKey = studentPubKey;
        this.universityPubKey = universityPubKey;
    }

    @method()
    static parseGPA(msg: ByteString): bigint {
        return Utils.fromLEUnsigned(slice(msg,0n,16n));
    }

    @method()
    public unlock(msg: ByteString, sig: RabinPubKey, winnerSig: Sig, studenSig: Sig){
        assert(this.checkSig(studenSig, this.studentPubKey),"ChcekSig Failed!");
        assert(
            RabinVerifierWOC.verifySig(msg, sig, this.oraclePubKey),
            "Oracle sig verify failed!"
        );
        const studentGPA = Scholarship.parseGPA(msg);
        
        if(studentGPA >= this.targetGPA){
            const winner = this.studentPubKey;
            assert(this.checkSig(winnerSig, winner),"ChcekSig Failed!");
        }
    }


}