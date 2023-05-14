package digital.paynetics.phos.kernel.visa.cvm;


import digital.paynetics.phos.kernel.common.emv.kernel.common.ApplicationCryptogramType;
import digital.paynetics.phos.kernel.common.emv.kernel.common.TlvMap;
import digital.paynetics.phos.kernel.common.misc.PreprocessedApplication;


public interface VisaCvmSelection {
    VisaCvmSelectionResult process(TlvMap tlvDb,
                                   PreprocessedApplication app,
                                   byte[] ctq, ApplicationCryptogramType act);
}
