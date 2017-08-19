/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package net.sourceforge.spnego;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/**
 * Class adds capability to track/determine if the HTTP Status 
 * code has been set.
 * 
 * <p>
 * Also allows the ability to set the content length to zero 
 * and flush the buffer immediately after setting the HTTP 
 * Status code.
 * </p>
 * 
 * @author Darwin V. Felix
 * 
 */
public final class SpnegoHttpServletResponse extends HttpServletResponseWrapper  {

    private transient boolean statusSet = false;

    /**
     * 
     * @param response
     */
    public SpnegoHttpServletResponse(final HttpServletResponse response) {
        super(response);
    }

    /**
     * Tells if setStatus has been called.
     * 
     * @return true if HTTP Status code has been set
     */
    public boolean isStatusSet() {
        return this.statusSet;
    }

    @Override
    public void setStatus(final int status) {
        super.setStatus(status);
        this.statusSet = true;
    }

    /**
     * Sets the HTTP Status Code and optionally set the the content 
     * length to zero and flush the buffer.
     * 
     * @param status http status code
     * @param immediate set to true to set content len to zero and flush
     * @throws IOException 
     * 
     * @see #setStatus(int)
     */
    public void setStatus(final int status, final boolean immediate) throws IOException {
        setStatus(status);
        if (immediate) {
            setContentLength(0);
            flushBuffer();
        }
    }
}
