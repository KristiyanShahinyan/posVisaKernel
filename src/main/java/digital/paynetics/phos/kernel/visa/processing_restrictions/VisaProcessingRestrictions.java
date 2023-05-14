package digital.paynetics.phos.kernel.visa.processing_restrictions;

import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.misc.CountryCode;


public interface VisaProcessingRestrictions {
    VisaProcessingRestrictionsResult process(TlvMap tlvDb,
                                             TransactionData transactionData,
                                             CountryCode terminalCountryCode,
                                             byte[] ctq,
                                             boolean isVisaAucCashbackCheckEnabled,
                                             boolean isVisaAucManualCashCheckEnabled) throws EmvException, TlvException;

}
