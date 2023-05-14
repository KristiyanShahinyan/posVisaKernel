package digital.paynetics.phos.kernel.visa;

import digital.paynetics.phos.kernel.common.crypto.EncDec;
import digital.paynetics.phos.kernel.common.emv.Outcome;
import digital.paynetics.phos.kernel.common.emv.entry_point.misc.TransactionData;
import digital.paynetics.phos.kernel.common.emv.entry_point.selection.SelectedApplication;
import digital.paynetics.phos.kernel.common.emv.kernel.common.Kernel;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.misc.CountryCode;
import digital.paynetics.phos.kernel.common.misc.TransactionTimestamp;
import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public interface VisaKernel extends Kernel {
    Outcome process(Transceiver transceiver,
                    TlvMap commonDolData,
                    CountryCode countryCode,
                    TransactionData transactionData,
                    SelectedApplication selectedApp,
                    TransactionTimestamp ts,
                    EncDec encDec
    );

}
