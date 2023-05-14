package digital.paynetics.phos.kernel.visa.afl;

import java.io.IOException;

import digital.paynetics.phos.kernel.common.nfc.transceiver.Transceiver;


public interface VisaAflProcessor {
    VisaAflProcessorResult process(Transceiver transceiver, byte[] applicationFileLocator)
            throws IOException;
}
