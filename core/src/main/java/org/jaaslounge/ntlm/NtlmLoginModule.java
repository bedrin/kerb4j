package org.jaaslounge.ntlm;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.security.auth.login.FailedLoginException;

import jcifs.UniAddress;
import jcifs.rap.group.GroupUsersInfo;
import jcifs.rap.user.UserManagement;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbSession;

import org.jaaslounge.AbstractLoginModule;

public class NtlmLoginModule extends AbstractLoginModule
{

	private GroupUsersInfo[] groups;

	private List userGroups;

	private String domain;

	private String host;

        private String user;

        private String passwd;
        
        public NtlmLoginModule()
        {
          // Do nothing - but needed
        }        

  		public NtlmLoginModule(String strHost,String strDomain)
        {
          	// Constructor only needed for Test GUI
        	this.host=strHost;
                this.domain=strDomain;
        }

        public void connect(String strUser,String strPasswd)
        {
          try
          {
            this.user=strUser;
            this.passwd=strPasswd;

            if (host==null)
	            throw new FailedLoginException("Controler host has not been specified");

	    if (isDebug()) {
	            System.out.println("["+getClass().getName()+"] host: "+host);
	            System.out.println("["+getClass().getName()+"] domain: "+domain);
	    }
	    NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, user, passwd);

	    UserManagement umgt = new UserManagement(host, auth);
	    try {
	        userGroups=null;
	        InetAddress ip = InetAddress.getByName(host);
                UniAddress domain = new UniAddress(ip);
	        SmbSession.logon(domain,auth);
	        groups=umgt.netUserGetGroups(user,0);
	        System.out.println("["+getClass().getName()+"] authentication successfull");
	        System.out.println("["+getClass().getName()+"] groups : "+Arrays.toString(groups));
	    } catch (Exception e)
            {
	        if (isDebug())
	            System.out.println("["+getClass().getName()+"] authentication failed");
	        throw new FailedLoginException(e.getMessage());
	    }
          }
          catch (FailedLoginException ex)
          {
            System.out.println("FailedLoginException: " + ex.getMessage());
          }


          

        }

	protected void _initialize() {
		host=(String)getOptions().get("host");
		domain=(String)getOptions().get("domain");
	}

	public void authenticate() throws FailedLoginException {
		if (host==null)
			throw new FailedLoginException("Controler host has not been specified");
		if (isDebug()) {
			System.out.println("["+getClass().getName()+"] host: "+host);
			System.out.println("["+getClass().getName()+"] domain: "+domain);
		}
		NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, getUsername(), new String(getPassword()));

		UserManagement umgt = new UserManagement(host, auth);
		try {
		    userGroups=null;
		    InetAddress ip = InetAddress.getByName(host);
			UniAddress domain = new UniAddress(ip);
		    SmbSession.logon(domain,auth);
		    groups=umgt.netUserGetGroups(getUsername(),0);
		} catch (Exception e) {
		    if (isDebug())
		        System.out.println("["+getClass().getName()+"] authentication failed");
		    throw new FailedLoginException(e.getMessage());
		}
	}

    public Collection getUserGroups() {
        if (userGroups==null) {
            userGroups = new ArrayList();
            for (int i=0;i<groups.length;i++)
                userGroups.add(groups[i].name);
        }
        return userGroups;
    }
}
