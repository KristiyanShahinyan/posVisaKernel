package digital.paynetics.phos.kernel.visa;

import org.slf4j.LoggerFactory;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;


public class VisaMandatoryDataCheckerImpl implements VisaMandatoryDataChecker {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    @Inject
    public VisaMandatoryDataCheckerImpl() {
    }


    @Override
    public boolean isPresent(TlvMap tlvDb) {
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_CRYPTOGRAM)) {
            logger.warn("Missing mandatory field: APP_CRYPTOGRAM");
            return false;
        }

        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_INTERCHANGE_PROFILE)) {
            logger.warn("Missing mandatory field: APPLICATION_INTERCHANGE_PROFILE");
            return false;
        }

        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.APP_TRANSACTION_COUNTER)) {
            logger.warn("Missing mandatory field: APP_TRANSACTION_COUNTER");
            return false;
        }

        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.ISSUER_APPLICATION_DATA)) {
            logger.warn("Missing mandatory field: ISSUER_APPLICATION_DATA");
            return false;
        }

//        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_CARD_TRANSACTION_QUALIFIERS)) {
//            return false;
//        }

        //noinspection RedundantIfStatement
        if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK_2_EQV_DATA)) {
            logger.warn("Missing mandatory field: TRACK_2_EQV_DATA");
            return false;
        }

        return true;
    }
}
