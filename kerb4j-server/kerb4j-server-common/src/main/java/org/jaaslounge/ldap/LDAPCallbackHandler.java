package org.jaaslounge.ldap;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class LDAPCallbackHandler implements CallbackHandler
{
    private String _sUsername=null; // Username
    private String _sPasswd=null;   // Password

    public LDAPCallbackHandler()
    {
      // nothing todo
    }

    public LDAPCallbackHandler(String username,String passwd)
    {
      // set parameter
      _sUsername=username;
      _sPasswd=passwd;
    }

    public void handle(Callback[] callbacks) throws java.io.IOException, UnsupportedCallbackException
    {
            // go throw given callbacks
            for (int i = 0; i < callbacks.length; i++)
            {
                if (callbacks[i] instanceof NameCallback)
                {
                  // Callback for username
                  NameCallback namecallback = (NameCallback) callbacks[i];
                  // check if username is null
                  if (_sUsername==null)
                  {
                    // write message to system prompt
                    System.out.print(namecallback.getPrompt());
                    // get username from system prompt
                    namecallback.setName(new BufferedReader(new InputStreamReader(System.in)).readLine());
                  }
                  else
                  {
                    // set given username
                    namecallback.setName(_sUsername);
                  }
                }
                else if (callbacks[i] instanceof PasswordCallback)
                {
                  // Callback for password
                  PasswordCallback passwordcallback = (PasswordCallback)callbacks[i];
                  // check if given password is null
                  if (_sPasswd==null)
                  {
                    // write message to system prompt
                    System.out.print(passwordcallback.getPrompt());
                    // set password from system promtp
                    passwordcallback.setPassword(new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray());
                  }
                  else
                  {
                    // set given password
                    passwordcallback.setPassword(_sPasswd.toCharArray());
                  }
                }
                else
                {
                  throw new UnsupportedCallbackException(callbacks[i]);
                }
            }
    }
}


