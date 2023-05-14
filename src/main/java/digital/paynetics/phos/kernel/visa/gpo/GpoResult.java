package digital.paynetics.phos.kernel.visa.gpo;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;


/**
 * Encapsulates the result of the execution of GET PROCESSING OPTIONS
 * If {@link #isOk} returns false then outcome is present
 * If {@link #isOk} returns true then fortlvDb is present
 * <p>
 * Use the static factory methods to create instance (constructor is private for safety reasons).
 */
public final class GpoResult {
    private final boolean isOk;
    private final Outcome outcome;
    private final List<Tlv> fortlvDb;


    private GpoResult(boolean isOk,
                      Outcome outcome,
                      List<Tlv> fortlvDb) {

        this.isOk = isOk;
        this.outcome = outcome;
        this.fortlvDb = fortlvDb;
    }


    public static GpoResult createOkResult(List<Tlv> fortlvDb) {
        return new GpoResult(true, null, fortlvDb);
    }


    public static GpoResult createFailResult(Outcome outcome) {
        return new GpoResult(false, outcome, null);
    }


    /**
     * Indicated success of the GPO execution
     *
     * @return true if GPO execution and processing was successful, false otherwise
     */
    public boolean isOk() {
        return isOk;
    }


    public Outcome getOutcome() {
        return outcome;
    }


    /**
     * Returns list of TLVs that have to be added to the 'data record'
     *
     * @return List ot TLVs
     */
    public List<Tlv> getForTlvDb() {
        return fortlvDb;
    }
}
