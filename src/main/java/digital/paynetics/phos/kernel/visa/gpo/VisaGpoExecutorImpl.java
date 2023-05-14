package digital.paynetics.phos.kernel.visa.gpo;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.tag.TlvUtils;
import digital.paynetics.phos.kernel.common.emv.ui.ContactlessTransactionStatus;
import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.common.nfc.ApduCommand;
import digital.paynetics.phos.kernel.common.nfc.ApduCommandPackage;
import digital.paynetics.phos.kernel.common.nfc.ApduResponsePackage;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public class VisaGpoExecutorImpl implements VisaGpoExecutor {
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final List<Tlv> fortlvDb = new ArrayList<>();


    @Inject
    public VisaGpoExecutorImpl() {
    }


    @Override
    public GpoResult execute(Transceiver transceiver, byte[] pdolPrepared) throws IOException {
        logger.debug("About to execute GET PROCESSING OPTIONS");
        try {
            ApduCommandPackage cmd = new ApduCommandPackage(ApduCommand.GPO, pdolPrepared);
            // 5.2.2.1
            ApduResponsePackage respGpo = transceiver.transceive(cmd);

            if (respGpo.isSuccess()) {
                parse(respGpo.getData());
                respGpo.purgeData();
                return GpoResult.createOkResult(fortlvDb);
            } else {
                respGpo.purgeData();
                Outcome.Builder b;
                UserInterfaceRequest ui;
                switch (respGpo.getStatusWord()) {
                    case SW_6984:
                        ui = new UserInterfaceRequest(StandardMessages.INSERT_CARD,
                                ContactlessTransactionStatus.PROCESSING_ERROR, 0, null, null, 0, null);

                        b = new Outcome.Builder(Outcome.Type.TRY_ANOTHER_INTERFACE);
                        b.uiRequestOnOutcome(ui);

                        return GpoResult.createFailResult(b.build());
                    case SW_6985:
                        b = new Outcome.Builder(Outcome.Type.SELECT_NEXT);
                        return GpoResult.createFailResult(b.build());
                    case SW_6986:
                        ui = new UserInterfaceRequest(StandardMessages.SEE_PHONE_FOR_INSTRUCTIONS,
                                ContactlessTransactionStatus.PROCESSING_ERROR, 13, null, null, 0, null);

                        b = new Outcome.Builder(Outcome.Type.TRY_AGAIN);
                        b.uiRequestOnOutcome(ui);
                        return GpoResult.createFailResult(b.build());
                    default:
                        // this should not happen according to C-3, so we improvise with createTryAnotherCardOutcome()
                        return GpoResult.createFailResult(Outcome.createTryAnotherCardOutcome(null));
                }
            }
        } catch (TlvException | EmvException e) {
            logger.warn(e.getMessage());
            return parsingError();
        }
    }


    void parse(byte[] data) throws TlvException, EmvException {
        // According to VCPS 2.2 G.2 GET PROCESSING OPTIONS (GPO) Command-Response APDUs
        // only format 2 is supported

        logger.debug("GPO Template 2");
        List<Tlv> list = TlvUtils.getChildTlvs(data, EmvTag.RESPONSE_MESSAGE_TEMPLATE_2);
        if (list.size() > 0) {
            for (Tlv item : list) {
                if (item.getTag() == EmvTag.APPLICATION_FILE_LOCATOR) {
                    int length = item.getValueBytes().length;

                    // Visa allows empty (zero length) AFL according to the ICC test tool
                    // however no where in the specs that is mentioned, i.e.
                    // VCPS 2.2 G.2 GET PROCESSING OPTIONS (GPO) Command-Response APDUs
                    if (length > 248 || (length % 4 != 0)) {
                        throw new EmvException("Invalid APPLICATION_FILE_LOCATOR length");
                    }
                    fortlvDb.add(item);
                } else if (item.getTag() == EmvTag.APPLICATION_INTERCHANGE_PROFILE) {
                    if (item.getLength() != 2) {
                        throw new EmvException("Invalid APPLICATION_INTERCHANGE_PROFILE length");
                    }
                    fortlvDb.add(item);
                } else {
                    fortlvDb.add(item);
                }
            }
        } else {
            throw new EmvException("Empty GPO Template 2");
        }
    }


    private GpoResult parsingError() {
        return GpoResult.createFailResult(Outcome.createTryAnotherCardOutcome(null));
    }
}
