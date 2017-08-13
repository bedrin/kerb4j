package com.kerb4j.spnego;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1Flags;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

import java.util.ArrayList;
import java.util.List;

import static com.kerb4j.spnego.NegTokenInit.AuthorizationDataEntryField.*;

public class NegTokenInit extends KrbSequenceType {

    /**
     * The possible fields
     */
    protected enum AuthorizationDataEntryField implements EnumType {
        SPNEGO_TOKEN_INIT_MECH_TYPES,
        SPNEGO_TOKEN_INIT_REQ_FLAGS,
        SPNEGO_TOKEN_MECH_TOKEN,
        SPNEGO_TOKEN_MECH_LIST_MIC;

        /**
         * {@inheritDoc}
         */
        @Override
        public int getValue() {
            return ordinal();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getName() {
            return name();
        }
    }

    /** The AuthorizationDataEntry's fields */
    private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(SPNEGO_TOKEN_INIT_MECH_TYPES, KrbObjectIds.class),
            new ExplicitField(SPNEGO_TOKEN_INIT_REQ_FLAGS, Asn1Flags.class),
            new ExplicitField(SPNEGO_TOKEN_MECH_TOKEN, Asn1OctetString.class),
            new ExplicitField(SPNEGO_TOKEN_MECH_LIST_MIC, Asn1OctetString.class),
    };

    public NegTokenInit() {
        super(fieldInfos);
    }

    public List<String> getMechTypes() {
        List<String> mechTypes = new ArrayList<String>();
        for (Asn1ObjectIdentifier objId : getFieldAs(SPNEGO_TOKEN_INIT_MECH_TYPES, KrbObjectIds.class).getElements()) {
            mechTypes.add(objId.getValue());
        }
        return mechTypes;
    }

    public Asn1Flags getReqFlags() {
        return getFieldAs(SPNEGO_TOKEN_INIT_REQ_FLAGS, Asn1Flags.class);
    }

    public byte[] getMechToken() {
        return getFieldAsOctets(SPNEGO_TOKEN_MECH_TOKEN);
    }

    public byte[] getMechListMIC() {
        return getFieldAsOctets(SPNEGO_TOKEN_MECH_LIST_MIC);
    }

}
