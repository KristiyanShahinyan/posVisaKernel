package digital.paynetics.phos.kernel.visa.processing_restrictions;

import digital.paynetics.phos.kernel.common.emv.Outcome;


public final class VisaProcessingRestrictionsResult {
    private final boolean isDeclineRequired;
    private final Outcome outcome;


    private VisaProcessingRestrictionsResult(boolean isDeclineRequired, Outcome outcome) {
        this.isDeclineRequired = isDeclineRequired;
        this.outcome = outcome;
    }


    public static VisaProcessingRestrictionsResult createDeclineRequiredResult() {
        return new VisaProcessingRestrictionsResult(true, null);
    }


    public static VisaProcessingRestrictionsResult createTryAnotherInterfaceOutcomeResult() {
        return new VisaProcessingRestrictionsResult(false, Outcome.createTryAnotherInterface(null));
    }


    public static VisaProcessingRestrictionsResult createNeutralResult() {
        return new VisaProcessingRestrictionsResult(false, null);
    }


    public boolean isDeclineRequired() {
        return isDeclineRequired;
    }


    public Outcome getOutcome() {
        return outcome;
    }
}
