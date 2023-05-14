package digital.paynetics.phos.kernel.visa.processing_restrictions;

import java.math.BigInteger;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationUsageControl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.misc.CountryCode;
import digital.paynetics.phos.kernel.common.misc.TransactionType;


public class VisaProcessingRestrictionsImpl implements VisaProcessingRestrictions {
    @Inject
    public VisaProcessingRestrictionsImpl() {
    }


    @Override
    public VisaProcessingRestrictionsResult process(TlvMap tlvDb,
                                                    TransactionData transactionData,
                                                    CountryCode terminalCountryCode,
                                                    byte[] ctq,
                                                    boolean isVisaAucCashbackCheckEnabled,
                                                    boolean isVisaAucManualCashCheckEnabled
    ) throws EmvException, TlvException {


        BigInteger ctqByte1Bi = null;
        if (ctq != null) {
            if (ctq.length != 2) {
                throw new IllegalArgumentException("Invalid ctq length: " + ctq.length);
            }
            ctqByte1Bi = BigInteger.valueOf(ctq[0]);
        }


        // we first check the case when APP_USAGE_CONTROL or ISSUER_COUNTRY_CODE is missing to simplify the other checks
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_USAGE_CONTROL) ||
                !tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_COUNTRY_CODE)) {

            if (transactionData.getType() == TransactionType.CASH_ADVANCE) {
                if (isVisaAucManualCashCheckEnabled) {
                    if (ctqByte1Bi != null && ctqByte1Bi.testBit(3 - 1)) {
                        return VisaProcessingRestrictionsResult.createTryAnotherInterfaceOutcomeResult();
                    } else {
                        return VisaProcessingRestrictionsResult.createDeclineRequiredResult();
                    }
                } else {
                    return VisaProcessingRestrictionsResult.createNeutralResult();
                }
            } else if (transactionData.getType() == TransactionType.CASHBACK) {
                if (isVisaAucCashbackCheckEnabled) {
                    if (ctqByte1Bi != null && ctqByte1Bi.testBit(2 - 1)) {
                        return VisaProcessingRestrictionsResult.createTryAnotherInterfaceOutcomeResult();
                    } else {
                        return VisaProcessingRestrictionsResult.createDeclineRequiredResult();
                    }
                } else {
                    return VisaProcessingRestrictionsResult.createNeutralResult();
                }
            } else {
                return VisaProcessingRestrictionsResult.createNeutralResult();
            }
        }


        Tlv tlvAuc = tlvDb.get(EmvTag.APP_USAGE_CONTROL);
        ApplicationUsageControl auc = new ApplicationUsageControl(tlvAuc.getValueBytes());

        int issuerCountryCode = tlvDb.get(EmvTag.ISSUER_COUNTRY_CODE).getValueAsBcdInt();

        // 5.5.1.3
        if (transactionData.getType() == TransactionType.CASH_ADVANCE) {
            if (isVisaAucManualCashCheckEnabled) {
                if (terminalCountryCode.getNumeric() == issuerCountryCode) {
                    if (auc.isValidForDomesticCash()) {
                        return VisaProcessingRestrictionsResult.createNeutralResult();
                    } else {
                        if (ctqByte1Bi != null && ctqByte1Bi.testBit(3 - 1)) {
                            return VisaProcessingRestrictionsResult.createTryAnotherInterfaceOutcomeResult();
                        } else {
                            return VisaProcessingRestrictionsResult.createDeclineRequiredResult();
                        }
                    }
                } else {
                    if (auc.isValidForInternationalCash()) {
                        return VisaProcessingRestrictionsResult.createNeutralResult();
                    } else {
                        if (ctqByte1Bi != null && ctqByte1Bi.testBit(3 - 1)) {
                            return VisaProcessingRestrictionsResult.createTryAnotherInterfaceOutcomeResult();
                        } else {
                            return VisaProcessingRestrictionsResult.createDeclineRequiredResult();
                        }
                    }
                }
            } else {
                return VisaProcessingRestrictionsResult.createNeutralResult();
            }
        } else if (transactionData.getType() == TransactionType.CASHBACK) {
            if (isVisaAucCashbackCheckEnabled) {
                if (terminalCountryCode.getNumeric() == issuerCountryCode) {
                    if (auc.isDomesticCashbackAllowed()) {
                        return VisaProcessingRestrictionsResult.createNeutralResult();
                    } else {
                        if (ctqByte1Bi != null && ctqByte1Bi.testBit(2 - 1)) {
                            return VisaProcessingRestrictionsResult.createTryAnotherInterfaceOutcomeResult();
                        } else {
                            return VisaProcessingRestrictionsResult.createDeclineRequiredResult();
                        }
                    }
                } else {
                    if (auc.isInternationalCashbackAllowed()) {
                        return VisaProcessingRestrictionsResult.createNeutralResult();
                    } else {
                        if (ctqByte1Bi != null && ctqByte1Bi.testBit(2 - 1)) {
                            return VisaProcessingRestrictionsResult.createTryAnotherInterfaceOutcomeResult();
                        } else {
                            return VisaProcessingRestrictionsResult.createDeclineRequiredResult();
                        }
                    }
                }
            } else {
                return VisaProcessingRestrictionsResult.createNeutralResult();
            }
        } else {
            return VisaProcessingRestrictionsResult.createNeutralResult();
        }
    }
}
