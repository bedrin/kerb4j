package com.kerb4j.server.marshall.pac;

import com.kerb4j.server.marshall.Kerb4JException;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Structure representing the S4U_DELEGATION_INFO record
 * 
 * @author bugeaud at gmail dot com
 */
public class PacDelegationInfo {

    private String proxyTarget;
    private List<String> transitedServices;
		
    public PacDelegationInfo(byte[] data) throws Kerb4JException {
        try {
            final PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(
                    new ByteArrayInputStream(data)));

            // Skip firsts
            // Jaaslounge is assuming here that the DREP Header of the RPC marshaling will always be the same :
            // Byte Order = LE, HDR Length = 9 ...
            pacStream.skipBytes(20);

            final PacUnicodeString proxyTargetString = pacStream.readUnicodeString();
                        
            final int transitedListSize = pacStream.readInt();
            final PacUnicodeString[] transitedServiceStrings = new PacUnicodeString[transitedListSize];
            
            // skip the pointer that should be 0x2008 as per NDR encoding
            pacStream.skipBytes(4);
            proxyTarget = proxyTargetString.check(pacStream.readString());
            
            final int listSize = pacStream.readInt();
            
            if(transitedListSize!=listSize) throw new Kerb4JException("pac.delegationinfo.transitedlist.sizenotmatching");
            
            for(int i=0;i<listSize;i++){
            	transitedServiceStrings[i] = pacStream.readUnicodeString();
            }
            
            // Read the actual string and compare with anticipated size from the UNICODE_STRING zone
            final String[] transitedServices = new String[transitedListSize];
            
            for(int i=0;i<transitedListSize;i++){
            	transitedServices[i]= transitedServiceStrings[i].check(pacStream.readString());	
            }
        	
            this.transitedServices = Collections.unmodifiableList(Arrays.asList(transitedServices));
        } catch(IOException e) {
            throw new Kerb4JException("pac.delegationinfo.malformed", null, e);
        }
    }

    public String getProxyTarget(){
    	return proxyTarget;
    }
    
    public List<String> getTransitedServices(){
    	return transitedServices;
    }

}
