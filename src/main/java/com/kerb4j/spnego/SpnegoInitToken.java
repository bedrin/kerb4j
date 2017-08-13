package com.kerb4j.spnego;

import com.kerb4j.Kerb4JException;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;

import java.io.IOException;
import java.nio.ByteBuffer;

public class SpnegoInitToken extends SpnegoToken {

    private String[] mechanisms;
    private int contextFlags;

    public SpnegoInitToken(byte[] token) throws Kerb4JException {
        try {

            Asn1ParseResult asn1ParseResult = Asn1Parser.parse(ByteBuffer.wrap(token));

            Asn1ParseResult item1 = ((Asn1Container) asn1ParseResult).getChildren().get(0);
            Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier();
            asn1ObjectIdentifier.decode(item1);

            if(!asn1ObjectIdentifier.getValue().equals(SpnegoConstants.SPNEGO_OID))
                throw new Kerb4JException("spnego.token.invalid", null, null);

            Asn1ParseResult item2 = ((Asn1Container) asn1ParseResult).getChildren().get(1);

            NegTokenInit negTokenInit = new NegTokenInit();
            negTokenInit.decode(((Asn1Container) item2).getChildren().get(0));

            mechanisms =
                    null == negTokenInit.getMechTypes() ? new String[0] :
                    negTokenInit.getMechTypes().toArray(new String[negTokenInit.getMechTypes().size()]);

            mechanism = mechanisms.length > 0 ? mechanisms[0] : null;

            contextFlags = null == negTokenInit.getReqFlags() ? 0 : negTokenInit.getReqFlags().getFlags();

            mechanismToken = negTokenInit.getMechToken();

            mechanismList = negTokenInit.getMechListMIC();

        } catch(IOException e) {
            throw new Kerb4JException("spnego.token.malformed", null, e);
        }
    }

    public int getContextFlags() {
        return contextFlags;
    }

    public boolean getContextFlag(int flag) {
        return (getContextFlags() & flag) == flag;
    }

    public String[] getMechanisms() {
        return mechanisms;
    }

}
