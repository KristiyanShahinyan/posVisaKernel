package digital.paynetics.phos.kernel.visa;

import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;


public interface VisaMandatoryDataChecker {
    boolean isPresent(TlvMap tlvDb);
}
