package digital.paynetics.phos.kernel.visa.afl;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.Afl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.AflsExtractor;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public class VisaAflProcessorImpl implements VisaAflProcessor {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final AflsExtractor aflsExtractor;


    @Inject
    public VisaAflProcessorImpl(AflsExtractor aflsExtractor) {
        this.aflsExtractor = aflsExtractor;
    }


    @Override
    public VisaAflProcessorResult process(Transceiver transceiver, byte[] applicationFileLocator)
            throws IOException {

        List<Tlv> forTlvDb = new ArrayList<>();

        List<Afl> afls;
        try {
            afls = aflsExtractor.extractAfls(applicationFileLocator);
            if (afls.size() == 0) {
                throw new IllegalArgumentException();
            }

            for (Afl afl : afls) {
                if (afl.getSfi() != 0 && afl.getSfi() < 31) {
                    VisaAflProcessorResult rez = processSingleAfl(transceiver, afl);
                    if (rez.isOk()) {
                        forTlvDb.addAll(rez.getForTlvDb());
                    } else {
                        return rez;
                    }
                } else {
                    return parsingError();
                }
            }
            return VisaAflProcessorResult.createOkResult(forTlvDb);
        } catch (EmvException e) {
            return parsingError();
        }
    }


    /**
     * Processes single AFL by executing READ_RECORD for each of its records, and processes the response
     *
     * @param transceiver
     * @param afl
     * @return
     * @throws IOException
     */
    VisaAflProcessorResult processSingleAfl(Transceiver transceiver, Afl afl) throws IOException {
        List<Tlv> forTlvDb = new ArrayList<>();

        for (int index = afl.getFirstRecord(); index <= afl.getLastRecord(); index++) {
            ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.READ_RECORD, (byte) index,
                    (byte) ((afl.getSfi() << 3) | 4), null, 0);

            logger.debug("AFL {}, index {}", afl, index);

            ApduResponsePackage resp = transceiver.transceive(cmd);

            if (resp.isSuccess()) {
                try {
                    if (resp.getData().length > 0 && resp.getData()[0] == EmvTag.RECORD_TEMPLATE.getTagBytes()[0]) {
                        List<Tlv> children = TlvUtils.getChildTlvs(resp.getData(), EmvTag.RECORD_TEMPLATE);
                        resp.purgeData();
                        forTlvDb.addAll(children);
                    } else {
                        return parsingError();
                    }
                } catch (TlvException e) {
                    return parsingError();
                }
            } else {
                resp.purgeData();
                return VisaAflProcessorResult.createFailResult(Outcome.createTryAnotherCardOutcome(null));
            }
        }

        return VisaAflProcessorResult.createOkResult(forTlvDb);
    }


    private VisaAflProcessorResult parsingError() {
        return VisaAflProcessorResult.createFailResult(Outcome.createTryAnotherCardOutcome(null));
    }
}
