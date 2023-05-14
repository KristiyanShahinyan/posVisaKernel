package digital.paynetics.phos.kernel.visa;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.inject.Inject;

import digital.paynetics.phos.kernel.common.crypto.EncDec;
import digital.paynetics.phos.kernel.common.crypto.EncryptedItem;
import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.TtqFinal;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.MessageStore;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.entry_point.selection.SelectedApplication;
import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.EmvException;
import digital.paynetics.phos.kernel.common.emv.kernel.common.KernelType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.KernelUtils;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapImpl;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMapReadOnly;
import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.emv.tag.TlvException;
import digital.paynetics.phos.kernel.common.emv.ui.ContactlessTransactionStatus;
import digital.paynetics.phos.kernel.common.emv.ui.StandardMessages;
import digital.paynetics.phos.kernel.common.emv.ui.UserInterfaceRequest;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;
import digital.paynetics.phos.kernel.common.misc.CountryCode;
import digital.paynetics.phos.kernel.common.misc.PreprocessedApplication;
import digital.paynetics.phos.kernel.common.misc.Track2Data;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.misc.TransactionType;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;
import digital.paynetics.phos.kernel.visa.afl.VisaAflProcessor;
import digital.paynetics.phos.kernel.visa.afl.VisaAflProcessorResult;
import digital.paynetics.phos.kernel.visa.cvm.VisaCvmSelection;
import digital.paynetics.phos.kernel.visa.cvm.VisaCvmSelectionResult;
import digital.paynetics.phos.kernel.visa.gpo.GpoResult;
import digital.paynetics.phos.kernel.visa.gpo.VisaGpoExecutor;
import digital.paynetics.phos.kernel.visa.processing_restrictions.VisaProcessingRestrictions;
import digital.paynetics.phos.kernel.visa.processing_restrictions.VisaProcessingRestrictionsResult;
import java8.util.Optional;


public class VisaKernelImpl implements VisaKernel {
    private final VisaGpoExecutor gpoExecutor;
    private final VisaAflProcessor aflProcessor;
    private final VisaMandatoryDataChecker mandatoryDataChecker;
    private final VisaProcessingRestrictions processingRestrictions;
    private final VisaCvmSelection cvmSelection;
    private boolean isVisaAucCashbackCheckEnabled;
    private boolean isVisaAucManualCashCheckEnabled;

    private final org.slf4j.Logger logger = LoggerFactory.getLogger(this.getClass());

    private final TlvMap tlvDb = new TlvMapImpl();

    private final MessageStore messageStore;

    private EncDec encDec;

    private EncryptedItem track2EqvEnc;
    private EncryptedItem panEnc;


    @Inject
    public VisaKernelImpl(VisaGpoExecutor gpoExecutor,
                          VisaAflProcessor aflProcessor,
                          VisaMandatoryDataChecker mandatoryDataChecker,
                          VisaProcessingRestrictions processingRestrictions,
                          VisaCvmSelection cvmSelection, MessageStore messageStore) {

        this.gpoExecutor = gpoExecutor;
        this.aflProcessor = aflProcessor;
        this.mandatoryDataChecker = mandatoryDataChecker;
        this.processingRestrictions = processingRestrictions;
        this.cvmSelection = cvmSelection;
        this.messageStore = messageStore;
    }


    private static void prepareTlvDb(TlvMap tlvDb,
                                     TlvMapReadOnly commonDolData,
                                     SelectedApplication selectedApp) {

        Random random = new SecureRandom();
        byte[] tmp1 = new byte[random.nextInt(200)];
        random.nextBytes(tmp1);
        tlvDb.add(new Tlv(EmvTag.PHOS_OBFUSCATION1, tmp1.length, tmp1));
        byte[] tmp2 = new byte[random.nextInt(16)];
        random.nextBytes(tmp2);
        tlvDb.add(new Tlv(EmvTag.PHOS_OBFUSCATION2, tmp2.length, tmp2));
        byte[] tmp3 = new byte[random.nextInt(5)];
        random.nextBytes(tmp3);
        tlvDb.add(new Tlv(EmvTag.PHOS_OBFUSCATION3, tmp3.length, tmp3));

        for (Tlv tlv : commonDolData.asList()) {
            if (tlv.getTag() != EmvTag.TRANSACTION_TYPE) {
                tlvDb.updateOrAdd(tlv);
            } else {
                // Visa uses 0 for both cashback and purchase so we need to replace it...
                if (tlv.getValueBytes()[0] == 9) {
                    tlvDb.updateOrAdd(new Tlv(tlv.getTag(), 1, new byte[1]));
                } else {
                    tlvDb.updateOrAdd(tlv);
                }
            }
        }

        tlvDb.updateOrAdd(new Tlv(EmvTag.AID_TERMINAL, selectedApp.getDfName().length, selectedApp.getDfName()));
    }


    @Override
    public Outcome process(Transceiver transceiver,
                           TlvMap commonDolData,
                           CountryCode countryCode,
                           TransactionData transactionData,
                           SelectedApplication selectedApp,
                           TransactionTimestamp ts,
                           EncDec encDec) {

        this.encDec = encDec;

        prepareTlvDb(tlvDb, commonDolData, selectedApp);

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.PHOS_VISA_AUC_CASHBACK_ENABLED)) {
            isVisaAucCashbackCheckEnabled = tlvDb.get(EmvTag.PHOS_VISA_AUC_CASHBACK_ENABLED).getValueBytes()[0] != 0;
        }

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.PHOS_VISA_AUC_MANUAL_CASH_ENABLED)) {
            isVisaAucManualCashCheckEnabled = tlvDb.get(EmvTag.PHOS_VISA_AUC_MANUAL_CASH_ENABLED).getValueBytes()[0] != 0;
        }


        PreprocessedApplication app = selectedApp.getCandidate().getPreprocessedApplication();
        try {
            Optional<TtqFinal> ttqO = app.getTtq();
            if (!ttqO.isPresent()) {
                throw new IllegalStateException("TTQ is empty");
            }

            // for Visa we must set Online cryptogram required to 1 for online only readers (as ours)
            // Book C-3, A.2, TTQ
            byte[] ttqB = ttqO.get().toBytes();
            ttqB[1] |= 0b10000000;

            Tlv tlv = new Tlv(EmvTag.TERMINAL_TRANSACTION_QUALIFIERS__PUNATC_TRACK2, 4, ttqB);
            tlvDb.add(tlv);

            byte[] pdolData = KernelUtils.prepareDol(tlvDb, selectedApp.getPdol());
            byte[] pdolPrepared = KernelUtils.preparePdol(pdolData);

            GpoResult gpoResult = gpoExecutor.execute(transceiver, pdolPrepared);
            if (!gpoResult.isOk()) {
                // Outcome at this stage indicates some error in executing/processing GPO
                return gpoResult.getOutcome();
            }

            // 5.4.2.2
            TlvMap tmpMap = new TlvMapImpl();
            for (Tlv tlv2 : gpoResult.getForTlvDb()) {
                if (!tmpMap.isTagPresentAndNonEmpty(tlv2.getTag())) {
                    tmpMap.add(tlv2);
                } else {
                    if (!tlv2.getTag().isConstructed()) {
                        return Outcome.createTryAnotherCardOutcome(null);
                    }
                }
            }

            for (Tlv tlv2 : gpoResult.getForTlvDb()) {
                if (!tlvDb.isTagPresentAndNonEmpty(tlv2.getTag())) {
                    encAdd(tlv2);
                }
            }


            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.APPLICATION_FILE_LOCATOR)) {
                VisaAflProcessorResult rez = aflProcessor.process(transceiver,
                        tlvDb.get(EmvTag.APPLICATION_FILE_LOCATOR).getValueBytes());
                if (rez.isOk()) {
                    // 5.4.2.2
                    for (Tlv tlv2 : rez.getForTlvDb()) {
                        if (!tmpMap.isTagPresentAndNonEmpty(tlv2.getTag())) {
                            tmpMap.add(tlv2);
                        } else {
                            if (!tlv2.getTag().isConstructed()) {
                                return Outcome.createTryAnotherCardOutcome(null);
                            }
                        }
                    }

                    for (Tlv tlv2 : rez.getForTlvDb()) {
                        if (!tlvDb.isTagPresentAndNonEmpty(tlv2.getTag())) {
                            encAdd(tlv2);
                        }
                    }

                    // 5.4.1
                    cardReadOk();
                } else {
                    return rez.getOutcome();
                }
            } else {
                // 5.4.1
                cardReadOk();
            }


            // 5.4.2.1
            if (!mandatoryDataChecker.isPresent(tlvDb)) {
                return Outcome.createTryAnotherCardOutcome(null);
            }

            // Book C-3, A.2 Data Elements by Name, mismatch between Track 2 eqv and PAN

//            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.TRACK_2_EQV_DATA) &&
//                    tlvDb.isTagPresentAndNonEmpty(EmvTag.PAN)) {
            if (track2EqvEnc != null && panEnc != null) {
                byte[] pan = encDec.decrypt(panEnc);
                byte[] track2 = encDec.decrypt(track2EqvEnc);

                Track2Data track2Data = new Track2Data(track2);

                char[] panCh = ByteUtils.toHexChars(pan, false);
                boolean hadPadding = false;
                for (int i = 1; i < panCh.length; i++) {
                    if (panCh[i] == 'F') {
                        hadPadding = true;
                    }
                }
                char[] panCh2;
                if (hadPadding) {
                    panCh2 = Arrays.copyOfRange(panCh, 0, panCh.length - 1);
                } else {
                    panCh2 = panCh;
                }


                if (!Arrays.equals(track2Data.getPan(), panCh2)) {
                    logger.warn("PAN in TRACK 2 Eqv and PAN elements is different {}, {}", track2Data.getPan(),
                            tlvDb.get(EmvTag.PAN).getValueAsHex());
                    return Outcome.createTryAnotherCardOutcome(null);
                }

                track2Data.purge();
                ByteUtils.purge(pan);
                ByteUtils.purge(panCh);
                ByteUtils.purge(panCh2);
                ByteUtils.purge(track2);
            }


            byte[] cidRaw;
            if (!tlvDb.isTagPresentAndNonEmpty(EmvTag.CRYPTOGRAM_INFORMATION_DATA)) {
                // 5.4.3.1
                cidRaw = new byte[1];

                BigInteger tmp = BigInteger.valueOf(tlvDb.get(EmvTag.ISSUER_APPLICATION_DATA).getValueBytes()[4]);
                if (tmp.testBit(6 - 1)) {
                    cidRaw[0] = (byte) 0b10000000;
                }

                if (tmp.testBit(5 - 1)) {
                    cidRaw[0] = (byte) (cidRaw[0] | (byte) 0b01000000);
                }

                tlvDb.add(new Tlv(EmvTag.CRYPTOGRAM_INFORMATION_DATA, cidRaw.length, cidRaw));
                logger.debug("Card not returned CID, composed CID: {}", ByteUtils.toHexString(cidRaw));
            } else {
                Tlv cidTlv = tlvDb.get(EmvTag.CRYPTOGRAM_INFORMATION_DATA);
                cidRaw = cidTlv.getValueBytes();
                logger.debug("CID: {}", ByteUtils.toHexString(cidRaw));
            }

            ApplicationCryptogramType act = ApplicationCryptogramType.resolveType(cidRaw[0]);

            boolean isDeclineRequired = false;

            if (act == ApplicationCryptogramType.AAC &&
                    transactionData.getType() != TransactionType.REFUND) { // exception because of 3.4.1.2 (note)
                isDeclineRequired = true;
            }

            logger.debug("TTQ: {}", ByteUtils.toHexString(tlvDb.get(EmvTag.TERMINAL_TRANSACTION_QUALIFIERS__PUNATC_TRACK2).getValueBytes()));

            // skipping check in 5.4.3.2 for act == ApplicationCryptogramType.ARQC because ttq.isOnlineCryptoRequired is always true
            // Book C-3, A.2, TTQ/VSPS too
            boolean isOnlineRequired = true;

            if (act == ApplicationCryptogramType.UNKNOWN) {
                isDeclineRequired = true;
            }

            byte[] ctqRaw = null;
            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_CARD_TRANSACTION_QUALIFIERS)) {
                Tlv tlvCtq = tlvDb.get(EmvTag.VISA_CARD_TRANSACTION_QUALIFIERS);
                ctqRaw = tlvCtq.getValueBytes();
            }

            // Processing Restrictions
            // 5.5.1.1 - N/A - we don't support offline transactions
            // 5.5.1.2 - N/A - we don't support exceptions file

            // 5.5.1.3
            VisaProcessingRestrictionsResult prRez = processingRestrictions.process(tlvDb,
                    transactionData, countryCode, ctqRaw, isVisaAucCashbackCheckEnabled, isVisaAucManualCashCheckEnabled);

            if (prRez.getOutcome() != null) {
                return prRez.getOutcome();
            } else if (prRez.isDeclineRequired()) {
                isDeclineRequired = true;
            }

            Outcome.Cvm cvmRequested = Outcome.Cvm.NOT_APPLICABLE;
            if (!isDeclineRequired) {
//            if (!isDeclineRequired &&
//                    selectedApp.getCandidate().getPreprocessedApplication().getIndicators().isReaderCvmLimitExceeded()) {

                VisaCvmSelectionResult cvmRez = cvmSelection.process(tlvDb,
                        app,
                        ctqRaw,
                        act);

                cvmRequested = cvmRez.getCvm();

                // we ignore cvmRez.inOnlineRequired() because it is already true (always), see above
                if (cvmRez.isDeclineRequired()) {
                    isDeclineRequired = true;
                }

                // 5.7.1.3
                if (ttqO.get().isCvmRequired && cvmRez.getCvm() == Outcome.Cvm.NO_CVM) {
                    isDeclineRequired = true;
                }
            }



//            // 4.1.1.1
//            if (tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA)) {
//                Tlv tlvFfi = tlvDb.get(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA);
//                byte[] ffiRaw = tlvFfi.getValueBytes();
//                ffiRaw[3] = (byte) (ffiRaw[3] & 0b11110000);
//                Tlv tlvFfiNew = new Tlv(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA, ffiRaw.length, ffiRaw);
//                tlvDb.updateOrAdd(tlvFfiNew);
//            }

            // 5.8.1.1 - isOnlineRequired is always true, so suppressing
            //noinspection ConstantConditions
            if (!isDeclineRequired && isOnlineRequired) {
                UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.AUTHORIZING,
                        ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                        0, null, null, 0, null);
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.ONLINE_REQUEST);
                b.dataRecord(buildDataRecord());
                b.tlvDb(tlvDb.asList());
                b.cvm(cvmRequested);
                b.uiRequestOnOutcome(uiReq);

                return b.build();
            } else {
                // 5.9.1.1 - skip, isOnlineRequired is always true in our reader

                // 5.9.1.2
                UserInterfaceRequest uiReq = new UserInterfaceRequest(StandardMessages.NOT_AUTHORIZED,
                        ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                        0, null, null, 0, null);
                Outcome.Builder b = new Outcome.Builder(Outcome.Type.DECLINED);
                b.cvm(Outcome.Cvm.NO_CVM);
                b.uiRequestOnOutcome(uiReq);
                b.tlvDb(tlvDb.asList());

                return b.build();
            }

            // 5.9.1.3 - skip, we don't have another interface
        } catch (IOException e) {
            logger.warn("IOException: {}", e.getMessage());
            // 4.1.1.2
            return Outcome.createTryAgainOutcome(null);
        } catch (EmvException | TlvException e) {
            return Outcome.createTryAnotherCardOutcome(null);
        }
    }


    private void cardReadOk() {
        logger.debug("MSG: Card read OK");
        UserInterfaceRequest ui = new UserInterfaceRequest(StandardMessages.CARD_READ_OK_REMOVE_CARD,
                ContactlessTransactionStatus.CARD_READ_SUCCESSFULLY,
                0, null, null, 0, null);
        messageStore.set(ui);
    }


    @Override
    public KernelType getKernelType() {
        return KernelType.VISA;
    }


    @Override
    public int getAppKernelId() {
        return 3;
    }


    @Override
    public int getKernelApplicationVersion() {
        return 2;
    }


    @Override
    public boolean stopSignal() {
        // VISA does not have specific requirements for STOP, so we just ignore
        return true;
    }


    private List<Tlv> buildDataRecord() {
        TlvMap dataRecord = new TlvMapImpl();

        dataRecord.add(new Tlv(EmvTag.TERMINAL_VERIFICATION_RESULTS, 5, new byte[5]));
        tlvDb.add(new Tlv(EmvTag.TERMINAL_VERIFICATION_RESULTS, 5, new byte[5]));
        // B.1.1

        dataRecord.add(tlvDb.get(EmvTag.AMOUNT_AUTHORISED_NUMERIC));
        dataRecord.add(tlvDb.get(EmvTag.AMOUNT_OTHER_NUMERIC));
        dataRecord.add(tlvDb.get(EmvTag.APP_CRYPTOGRAM));
        dataRecord.add(tlvDb.get(EmvTag.APPLICATION_INTERCHANGE_PROFILE));
        dataRecord.add(tlvDb.get(EmvTag.APP_TRANSACTION_COUNTER));

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.PAN_SEQUENCE_NUMBER)) {
            dataRecord.add(tlvDb.get(EmvTag.PAN_SEQUENCE_NUMBER));
        }

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.MERCHANT_CUSTOM_DATA)) {
            dataRecord.add(tlvDb.get(EmvTag.MERCHANT_CUSTOM_DATA));
        }

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA)) {
            dataRecord.add(tlvDb.get(EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA));
        }

        if (tlvDb.isTagPresentAndNonEmpty(EmvTag.PAYMENT_ACCOUNT_REFFERENCE)) {
            dataRecord.add(tlvDb.get(EmvTag.PAYMENT_ACCOUNT_REFFERENCE));
        }


        dataRecord.add(tlvDb.get(EmvTag.ISSUER_APPLICATION_DATA));

        dataRecord.add(tlvDb.get(EmvTag.TERMINAL_COUNTRY_CODE));

        dataRecord.add(tlvDb.get(EmvTag.TRACK_2_EQV_DATA));

        dataRecord.add(tlvDb.get(EmvTag.TRANSACTION_CURRENCY_CODE));

        dataRecord.add(tlvDb.get(EmvTag.TRANSACTION_DATE));

        dataRecord.add(tlvDb.get(EmvTag.TRANSACTION_TYPE));

        dataRecord.add(tlvDb.get(EmvTag.UNPREDICTABLE_NUMBER));

        return dataRecord.asList();
    }


    private void encAdd(Tlv tlv) {
        if (tlv.getTag() != EmvTag.TRACK_2_EQV_DATA && tlv.getTag() != EmvTag.PAN) {
            tlvDb.add(tlv);
        } else {
            if (tlv.getTag() == EmvTag.TRACK_2_EQV_DATA) {
                tlvDb.add(new Tlv(EmvTag.TRACK_2_EQV_DATA, 1, new byte[1]));

                track2EqvEnc = encDec.encrypt(tlv.getValueBytes());
                tlvDb.add(new Tlv(EmvTag.PHOS_TRACK2_EQV_ENCRYPTED_DATA,
                        track2EqvEnc.getData().length,
                        track2EqvEnc.getData()));
                tlvDb.add(new Tlv(EmvTag.PHOS_TRACK2_EQV_ENCRYPTED_IV,
                        track2EqvEnc.getIv().length,
                        track2EqvEnc.getIv()));
            } else if (tlv.getTag() == EmvTag.PAN) {
                tlvDb.add(new Tlv(EmvTag.PAN, 1, new byte[1]));
                panEnc = encDec.encrypt(tlv.getValueBytes());
                tlvDb.add(new Tlv(EmvTag.PHOS_PAN_ENCRYPTED_DATA,
                        panEnc.getData().length,
                        panEnc.getData()));
                tlvDb.add(new Tlv(EmvTag.PHOS_PAN_ENCRYPTED_IV,
                        panEnc.getIv().length,
                        panEnc.getIv()));
            }

            tlv.purge();
        }
    }
}
