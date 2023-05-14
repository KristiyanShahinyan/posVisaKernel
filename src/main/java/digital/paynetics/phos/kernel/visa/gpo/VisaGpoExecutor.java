package digital.paynetics.phos.kernel.visa.gpo;

import java.io.IOException;

import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public interface VisaGpoExecutor {
    GpoResult execute(Transceiver transceiver, byte[] pdolPrepared) throws IOException;
}
