package digital.paynetics.phos.kernel.visa.misc;

import digital.paynetics.phos.kernel.common.emv.tag.EmvTag;
import digital.paynetics.phos.kernel.common.emv.tag.Tlv;
import digital.paynetics.phos.kernel.common.misc.ByteUtils;


enum FormFactorIndicator {
    NORMAL_CARD((byte) 0b00000000),
    MINI_CARD((byte) 0b00000001),
    NON_CARD_FORM_FACTOR((byte) 0b00000010),
    CONSUMER_MOBILE_PHONE((byte) 0b00000011),
    WRIST_WORN_DEVICE((byte) 0b00000100);

    private final byte value;


    FormFactorIndicator(byte value) {
        this.value = value;
    }


    public static FormFactorIndicator fromTlv(Tlv tlv) {
        if (tlv.getTag() != EmvTag.VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA) {
            throw new IllegalArgumentException("Must be TLV for VISA_FORM_FACTOR_INDICATOR__MS_THIRD_PARTY_DATA tag");
        }

        byte b = (byte) (tlv.getValueBytes()[0] & 0b00011111);

        FormFactorIndicator ret = null;
        for (FormFactorIndicator ffi: FormFactorIndicator.values()) {
            if (b == ffi.value) {
                ret = ffi;
                break;
            }
        }

        if (ret == null) {
            throw new IllegalArgumentException("Cannot create FormFactorIndicator from " + ByteUtils.toHexString(tlv.getValueBytes()));
        }

        return ret;
    }
}
