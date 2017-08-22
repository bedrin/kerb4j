package org.jaaslounge.ldap;

import java.util.List;
import java.util.Map;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.Subject;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.NamingException;
import java.util.ArrayList;

public class LDAPReader implements java.security.PrivilegedAction
{
  // LDAP Member
  private DirContext _cDirContext=null;

  // Membergroup name
  private List _cUserGroups=new ArrayList();
  private Map  _cMap=null;
  private boolean _bDebug=false;
  private String _sUser=null;
  private char[] _sPasswd=null;

  // Authentication Member
  private String _sLDAPServerURL=null;
  private String _sLDAPSuperUserContext=null;
  private String _sLDAPInitialContextFactory=null;

  // Optional Parameters
  private String _sLDAPSearchFilter=null;
  private boolean _sLDAPTruncateMemberOf=false;
  
  // Filter Members
  private String _sLDAPGroupSearch=null;
  private String _sLDAPClassName=null;
  private String _sLDAPUserSearch=null;

  public LDAPReader(Map opts,boolean isDebug,String sUser,char[] sPasswd) throws Exception
  {
    // Check Parameter
    if (opts!=null && sUser!=null && sPasswd!=null)
    {
      _bDebug = isDebug; // Set Debug level
      _cMap = opts;      // set parameter
      _sUser=sUser;      // set username
      _sPasswd=sPasswd;  // set password

      // Init Class - set member from parameter
      init();
    }
    else
      throw new Exception("LDAPReader(Map opts,boolean isDebug,CallbackHandler callback,String sUser,char[] sPasswd): Parameter null");
  }

  public Object run()
  {
      // start ldap connect
      LDAPConnect();
      return null;
  }

  public void LDAPConnect()
  {
    Hashtable env = new Hashtable(11);
    // Setting Parameter from JAAS Config File
    // LDAP Server URL
    env.put(Context.PROVIDER_URL,this._sLDAPServerURL);
    // LDAP Context Factory
    env.put(Context.INITIAL_CONTEXT_FACTORY,this._sLDAPInitialContextFactory);
    // LDAP Authentication - for the first time we support only GSSAPI (because it is secure)
    env.put(Context.SECURITY_AUTHENTICATION,"GSSAPI");
    // LDAP SASL qop
    env.put("javax.security.sasl.qop", "auth");

    try
    {
        // Init Context
        _cDirContext = new InitialDirContext(env);

        // Print all supported SASL mechanism for the given server
        if (_bDebug)
        {
          System.out.println("[" + getClass().getName() + "] "+ _cDirContext.getAttributes(_sLDAPServerURL,
                                                new String[] {"supportedSASLMechanisms"}).clone().toString());
        }

        SearchControls searchCtls = new SearchControls();

        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        // create filter
        String searchFilter;
        if (this._sLDAPSearchFilter != null)
        {
            searchFilter = this._sLDAPSearchFilter;
        }
        else
        {
            searchFilter = "(&(objectClass=user)(CN=%s*))";
//            searchFilter = "(&(objectClass=user)(userPrincipalName=%s*))";
        }

        searchFilter = ReplaceSearchParameter(searchFilter,_sUser);

        // Print search Filter
        if (_bDebug)
        {
	    System.out.println("[" + getClass().getName() + "]: searchFilter: "+ searchFilter);
        }
        
        // define returned attribs
        String returnedAtts[] ={"memberOf"};

        searchCtls.setReturningAttributes(returnedAtts);

        // search for objects
        NamingEnumeration answer = _cDirContext.search(_sLDAPSuperUserContext, searchFilter,searchCtls);

        // Loop through the search results
        while (answer.hasMoreElements())
        {
          SearchResult sr = (SearchResult) answer.next();

          // Print serach result
          if (_bDebug)
            System.out.println("[" + getClass().getName() + "] " + sr.getName());

          Attributes attrs = sr.getAttributes();

          if (attrs != null)
          {
            try
            {
              for (NamingEnumeration ae = attrs.getAll(); ae.hasMore(); )
              {
                Attribute attr = (Attribute) ae.next();

                if (_bDebug)
                  System.out.println("["+ getClass().getName()+"]: " + "Attribute: " + attr.getID());

                // enum elements
                for (NamingEnumeration e = attr.getAll(); e.hasMoreElements();)
                {
                  String strElement=e.nextElement().toString();

                  if (this._sLDAPTruncateMemberOf)
                  {
                      int cnloc = strElement.indexOf("CN=");
                      if (cnloc != -1)
                      {
                          int startloc = cnloc + 3;
                          int commaloc = strElement.indexOf(",", cnloc + 3);
                          int stoploc = commaloc;
                          strElement = strElement.substring(startloc, stoploc);
                      }
                  }
                  
                  if (_bDebug)
                    System.out.println("["+ getClass().getName()+"]: " + strElement);

                  // save group names into group list
                  _cUserGroups.add(strElement);
                }
              }
            }
            catch (NamingException e)
            {
              System.out.println("[" + getClass().getName() + "]: " + "Problem listing membership: " + e);
            }
          }
        }
        // close the context
        _cDirContext.close();

    } catch (NamingException e)
    {
        e.printStackTrace();
    }
  }

  private String ReplaceSearchParameter(String searchFilter, String user)
  {
      StringBuffer retbuf = new StringBuffer(searchFilter); 
      
      int userloc = retbuf.indexOf("%s");
      if (userloc != -1)
      {
          // Go into a loop to replace %s as many times as it exists
          while (userloc != -1)
          {
              retbuf.delete(userloc, userloc + 2);
              retbuf.insert(userloc, user);
//              ret = ret.substring(0, userloc) + user + 
//                  ret.substring(userloc + 2);
              userloc = retbuf.indexOf("%s");
          }
      }
      else
      { 
      }
      return(retbuf.toString());
  }
  
  private void init() throws Exception
  {
      // get Members from config file
      this._sLDAPServerURL=(String)             _cMap.get("LDAPServerURL");
      this._sLDAPSuperUserContext=(String)      _cMap.get("LDAPSuperUserContext");
      this._sLDAPInitialContextFactory=(String) _cMap.get("LDAPInitialContextFactory");
      this._sLDAPSearchFilter=(String)          _cMap.get("LDAPSearchFilter");
      String truncate=(String)                  _cMap.get("LDAPTruncateMemberOf");
      if (truncate == null) {
          this._sLDAPTruncateMemberOf=false;
      }
      else if ((truncate.equalsIgnoreCase("yes")) ||
               (truncate.equalsIgnoreCase("1")) ||
               (truncate.equalsIgnoreCase("on")) ||
               (truncate.equalsIgnoreCase("true"))) {
              this._sLDAPTruncateMemberOf = true;
      }
      else {
          this._sLDAPTruncateMemberOf=false;
      }

      // Check Members from file
      if (this._sLDAPServerURL==null)
        throw new Exception("Missing Parameter [LDAPServerURL]");
      else if (this._sLDAPSuperUserContext==null)
        throw new Exception("Missing Parameter [LDAPSuperUserContext]");
      else if (this._sLDAPInitialContextFactory==null)
        throw new Exception("Missing Parameter [LDAPInitialContextFactory]");
      else
      {
          if (_bDebug) // Debug Message
          {
            System.out.println("[" + this.getClass().getName() + "]: LDAPServerURL=" + this._sLDAPServerURL);
            System.out.println("[" + this.getClass().getName() + "]: LDAPSuperUserContext=" + this._sLDAPSuperUserContext);
            System.out.println("[" + this.getClass().getName() + "]: LDAPInitialContextFactory=" + this._sLDAPInitialContextFactory);
            System.out.println("[" + this.getClass().getName() + "]: LDAPSearchFilter=" + this._sLDAPSearchFilter);
            System.out.println("[" + this.getClass().getName() + "]: LDAPTruncateMemberOf=" + this._sLDAPTruncateMemberOf);
          } // isDebug()
        }
      }

  public void connect() throws Exception
  {

    // Set Kerberos Debug Mode
    if (_bDebug)
    {
      System.out.println("[" + getClass().getName() + "] sun.security.krb5.debug=true");
      System.setProperty("sun.security.krb5.debug", "true");
    }

    // Kerberos Authentication
    LoginContext context=null;

    try
    {
      if (_bDebug)
      {
        System.out.println("[" + getClass().getName() +"]: Kerberos Authentication start");
        System.out.println("[" + getClass().getName() +
                           "]: java.security.auth.login.config = " + System.getProperty("java.security.auth.login.config"));
      }

      // Login with CallbackHandler, with supplied password and user
      context=new LoginContext("Kerberos",new LDAPCallbackHandler(_sUser,new String(_sPasswd)));
      // kerberos login
      context.login();

      if (_bDebug)
        System.out.println("[" + getClass().getName() + "]: Kerberos Authentication succesful");

      // LDAP login
      Subject.doAs(context.getSubject(),this);

      if (_bDebug)
        System.out.println("[" + getClass().getName() + "]: LDAP Authentication succesful");

    }catch (LoginException ex)
    {
      if (_bDebug)
        System.out.println("[" + getClass().getName() + "]: Kerberos or LDAP Authentication failed");

      throw new Exception("LDAPReader()::connect: " + ex.getMessage());
    }
  }

  public List getMemberGroups()
  {
    return _cUserGroups;
  }
}
