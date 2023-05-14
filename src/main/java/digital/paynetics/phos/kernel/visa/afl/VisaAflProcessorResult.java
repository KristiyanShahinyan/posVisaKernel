package digital.paynetics.phos.kernel.visa.afl;

import java.util.List;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;


/**
 * Encapsulates result of processing an AFL
 * Use the static factory methods to create instances (constructor is private for safety reasons)
 */
public final class VisaAflProcessorResult {
    private final boolean isOk;
    private final Outcome outcome;
    private final List<Tlv> fortlvDb;


    private VisaAflProcessorResult(boolean isOk,
                                   Outcome outcome,
                                   List<Tlv> fortlvDb) {

        this.isOk = isOk;
        this.outcome = outcome;
        this.fortlvDb = fortlvDb;
    }


    public static VisaAflProcessorResult createOkResult(List<Tlv> fortlvDb) {

        return new VisaAflProcessorResult(true, null, fortlvDb);
    }


    public static VisaAflProcessorResult createFailResult(Outcome outcome) {

        return new VisaAflProcessorResult(false, outcome, null);
    }


    public boolean isOk() {
        return isOk;
    }


    /**
     * @return Outcome if {@link #isOk} returns false, null otherwise
     */
    public Outcome getOutcome() {
        return outcome;
    }


    public List<Tlv> getForTlvDb() {
        return fortlvDb;
    }
}
