/**
 * MIT License
 *
 * Copyright (c) 2016 Adrian CITU
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
package com.github.adriancitu.csrf;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Optional;

/**
 * 
 * @author Adrian CITU
 *
 */
public final class Util {
	public static final String GET_HTTP_METHOD = "GET";
	
	private Util() {
	}
	
	
	/**
	 * @param req the http request used to get the cookie.
	 * @param cookieName the cookie name.
	 * @return the first cookie having as name the parameter <code>cookieName</code>
	 * or {@link Optional#empty()} otherwise.
	 */
	public static Optional<Cookie> getFirstCookieByName(
			final HttpServletRequest req, 
			final String cookieName) {
		if (req.getCookies() == null) {
			return Optional.empty();
		}

		return Arrays.stream(req.getCookies())
				.filter(cookie -> cookieName.equals(cookie.getName()))
				.findFirst();
	}
}
