/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.sourceforge.spnego;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import org.jaaslounge.decoding.pac.PacLogonInfo;
import org.jaaslounge.decoding.pac.PacSid;

/**
 *
 * @author mtoele
 */
public class SpnegoLogonInfo {
	private PacLogonInfo logonInfo;

	public SpnegoLogonInfo(PacLogonInfo logonInfo) {
		this.logonInfo = logonInfo;
	}

	public String getUserSid() {
		return toString(logonInfo.getUserSid());
	}

	public String getUserName() {
		return logonInfo.getUserName();
	}

	public int getUserFlags() {
		return logonInfo.getUserFlags();
	}

	public String getUserDisplayName() {
		return logonInfo.getUserDisplayName();
	}

	public int getUserAccountControl() {
		return logonInfo.getUserAccountControl();
	}

	public String getServerName() {
		return logonInfo.getServerName();
	}

	public String[] getResourceGroupSids() {
		return toStringArray(logonInfo.getResourceGroupSids());
	}

	public Date getPwdMustChangeTime() {
		return logonInfo.getPwdMustChangeTime();
	}

	public Date getPwdLastChangeTime() {
		return logonInfo.getPwdLastChangeTime();
	}

	public Date getPwdCanChangeTime() {
		return logonInfo.getPwdCanChangeTime();
	}

	public String getProfilePath() {
		return logonInfo.getProfilePath();
	}

	public Date getLogonTime() {
		return logonInfo.getLogonTime();
	}

	public String getLogonScript() {
		return logonInfo.getLogonScript();
	}

	public short getLogonCount() {
		return logonInfo.getLogonCount();
	}

	public Date getLogoffTime() {
		return logonInfo.getLogoffTime();
	}

	public Date getKickOffTime() {
		return logonInfo.getKickOffTime();
	}

	public String getHomeDrive() {
		return logonInfo.getHomeDrive();
	}

	public String getHomeDirectory() {
		return logonInfo.getHomeDirectory();
	}

	public String[] getGroupSids() {
		return toStringArray(logonInfo.getGroupSids());
	}

	public String getGroupSid() {
		return toString(logonInfo.getGroupSid());
	}

	public String[] getExtraSids() {
		return toStringArray(logonInfo.getExtraSids());
	}

	public String getDomainName() {
		return logonInfo.getDomainName();
	}

	public short getBadPasswordCount() {
		return logonInfo.getBadPasswordCount();
	}

	private static String[] toStringArray(PacSid[] pacSids) {
		String[] stringSids;
		if(pacSids != null) {
			stringSids = new String[pacSids.length];
			for(int i = 0; i < pacSids.length; i++) {
				stringSids[i] = toString(pacSids[i]);
			}
		} else {
			stringSids = new String[0];
		}
		return stringSids;
	}

	private static String toString(PacSid pacSid) {
		return pacSid != null ? toString(pacSid.getBytes()) : "";
	}

	private static String toString(byte[] pacData) {
		StringBuilder stringSid = new StringBuilder(64);

		stringSid.append("S-");

		// sid revision
		stringSid.append(pacData[0]);

		// sid identifier authority
		stringSid.append("-");
		if(pacData[2] != 0 || pacData[3] != 0) {
			stringSid.append(String.format("0x%02x%02x%02x%02x%02x%02x",
							 0xFFFF & pacData[2], 0xFFFF & pacData[2], 0xFFFF & pacData[2],
							 0xFFFF & pacData[2], 0xFFFF & pacData[2], 0xFFFF & pacData[2]));
		} else {
			stringSid.append(getSidIdentifierAuthority(pacData));
		}


		int numSubAuthorities = pacData[1];
		for(int i = 0; i < numSubAuthorities; i++) {
			stringSid.append("-");
			stringSid.append(getSidSubAuthority(pacData, 8 + (i*4)));
		}

		return stringSid.toString();
	}

	// Note the difference in byte order between getSidIdentifierAuthority and getSidSubAuthority!
	private static BigInteger getSidIdentifierAuthority(byte[] pacData) {
		BigInteger res = BigInteger.ZERO;

		for(int i = 0; i < 4; i++) {
			res = res.shiftLeft(8);
			res = res.add(BigInteger.valueOf(pacData[4+i] & 0xFF));
		}

		return res;
	}

	// Note the difference in byte order between getSidIdentifierAuthority and getSidSubAuthority!
	private static BigInteger getSidSubAuthority(byte[] pacData, int offset) {
		BigInteger res = BigInteger.ZERO;

		for(int i = 3; i >= 0; i--) {
			res = res.shiftLeft(8);
			res = res.add(BigInteger.valueOf(pacData[offset+i] & 0xFF));
		}

		return res;
	}
}
