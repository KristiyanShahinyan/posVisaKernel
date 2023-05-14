package digital.paynetics.phos.kernel.visa.cvm;

import java.math.BigInteger;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TtqPreProcessing;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.PreprocessedApplication;


public class VisaCvmSelectionImpl implements VisaCvmSelection {
    @Inject
    public VisaCvmSelectionImpl() {
    }


    @Override
    public VisaCvmSelectionResult process(TlvMap tlvDb,
                                          PreprocessedApplication app,
                                          byte[] ctq, ApplicationCryptogramType act) {


        boolean isDeclineRequired = false;
        Outcome.Cvm cvmRequiredByCard = Outcome.Cvm.NO_CVM;

        TtqPreProcessing ttq = app.getIndicators().getTtq().get();

        // 5.7.1.1
        if (app.getIndicators().isReaderCvmLimitExceeded() &&
                !tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_CARD_TRANSACTION_QUALIFIERS)) {

            if (ttq.isSignatureSupported) {
                return new VisaCvmSelectionResult(Outcome.Cvm.OBTAIN_SIGNATURE, false, false);
            }

            //noinspection ConstantConditions - we check at the start of the method for TTQ presence
            if (ttq.isConsumerDeviceCvmSupported && ttq.isOnlinePinSupported) {
                return new VisaCvmSelectionResult(Outcome.Cvm.ONLINE_PIN, false, true);
            } else if (ttq.isConsumerDeviceCvmSupported) {
                isDeclineRequired = true;
            }
        }


        // 5.7.1.2
        if (ctq != null) { // if VISA_CARD_TRANSACTION_QUALIFIERS returned by card we will have ctqByte1Bi
            BigInteger ctqByte1Bi = BigInteger.valueOf(ctq[0]);
            BigInteger ctqByte2Bi = BigInteger.valueOf(ctq[1]);

            if (ctqByte1Bi.testBit(8 - 1) && ttq.isOnlinePinSupported) {
                return new VisaCvmSelectionResult(Outcome.Cvm.ONLINE_PIN, false, true);
            } else if (ctqByte2Bi.testBit(8 - 1)) {
                if (tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_CARD_AUTHENTICATION_RELATED_DATA__MASTERCARD_UDOL)) {
                    Tlv tlvCARD = tlvDb.get(EmvTag.VISA_CARD_AUTHENTICATION_RELATED_DATA__MASTERCARD_UDOL);
                    byte[] cardRaw = tlvCARD.getValueBytes();
                    if (cardRaw.length < 7) {
                        return new VisaCvmSelectionResult(cvmRequiredByCard, true, false);
                    }
                    if ((cardRaw[5] == ctq[0]) && (cardRaw[6] == ctq[1])) {
                        return new VisaCvmSelectionResult(Outcome.Cvm.CONFIRMATION_CODE_VERIFIED, isDeclineRequired,
                                false);
                    } else {
                        return new VisaCvmSelectionResult(cvmRequiredByCard, true, false);
                    }
                } else {
                    if (act == ApplicationCryptogramType.ARQC) {
                        return new VisaCvmSelectionResult(Outcome.Cvm.CONFIRMATION_CODE_VERIFIED, isDeclineRequired, false);
                    } else {
                        return new VisaCvmSelectionResult(cvmRequiredByCard, true, false);
                    }
                }
            } else {
                // skip test for Signature, we don't support
                if (ctqByte1Bi.testBit(7 - 1) && ttq.isSignatureSupported) {
                    return new VisaCvmSelectionResult(Outcome.Cvm.OBTAIN_SIGNATURE, false, false);
                } else {
                    return new VisaCvmSelectionResult(cvmRequiredByCard, isDeclineRequired, false);
                }
            }
        } else {
            return new VisaCvmSelectionResult(cvmRequiredByCard, isDeclineRequired, false);
        }
    }
}
