package digital.paynetics.phos.kernel.visa.cvm;

import digital.paynetics.phos.kernel.common.emv.Outcome;


public class VisaCvmSelectionResult {
    private final Outcome.Cvm cvm;
    private final boolean isDeclineRequired;
    private final boolean isOnlineRequired;


    public VisaCvmSelectionResult(Outcome.Cvm cvm, boolean isDeclineRequired, boolean isOnlineRequired) {
        this.cvm = cvm;
        this.isDeclineRequired = isDeclineRequired;
        this.isOnlineRequired = isOnlineRequired;
    }


    public Outcome.Cvm getCvm() {
        return cvm;
    }


    public boolean isDeclineRequired() {
        return isDeclineRequired;
    }


    public boolean isOnlineRequired() {
        return isOnlineRequired;
    }
}
