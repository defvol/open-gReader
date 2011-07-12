/*

Copyright 2011 Rodolfo Wilhelmy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


/** 
 * 
 * TEIGA Research @ http://teiga.mx 
 * 
 * A Google Reader API façade.
 * Handles secure authentication, subscription management, retrieving articles, tagging operations, etc.
 * 
 * @author rod@teiga.mx
 * @created June 17, 2011 
 * @updated July 12, 2011
 * 
 * References:
 * 
 * http://code.google.com/p/pyrfeed/wiki/GoogleReaderAPI
 * http://anirudhs.chaosnet.org/blog/2009.11.04.html
 * http://blog.martindoms.com/2009/08/15/using-the-google-reader-api-part-1/
 * 
 * TODO:
 * - Create a dictionary for error messages
 * - CAPTCHA requirement
 * 
 **/

package teiga
{
	import flash.events.Event;
	import flash.events.HTTPStatusEvent;
	import flash.events.IOErrorEvent;
	import flash.net.SharedObject;
	import flash.net.URLLoader;
	import flash.net.URLRequest;
	import flash.net.URLRequestHeader;
	import flash.net.URLVariables;
	import flash.utils.Dictionary;
	import flash.xml.XMLDocument;
	
	import json.JSON;
	
	import mx.rpc.xml.SimpleXMLDecoder;
		
	public class GoogleReader
	{
		// Constants		
		private static const SOURCE:String = 'teiga-greader-1.0';
		private static const STATE:String = 'user/-/state/com.google/';
		private static const API_ERROR:String = "Aw snap! Can't talk to Google Reader. Please try again later.";
		private static const HTTP_STATUS_FORBIDDEN:Number = 403;
		
		// Full URL		
		private static const READER_URL:String = 'https://www.google.com/reader';		
		private static const LOGIN_URL:String = 'https://www.google.com/accounts/ClientLogin';
		private static const TOKEN_URL:String = READER_URL + '/api/0/token';
		private static const SUBSCRIPTIONS_URL:String = READER_URL + '/api/0/subscription/list';
		private static const USERINFO_URL:String = READER_URL + '/api/0/user-info';
		
		// EDIT operations		
		private static const GET_ATOM:String = '/atom/';
		private static const EDIT_TAG:String =  '/api/0/edit-tag?client=' + SOURCE;
		private static const EDIT_SUBS:String = '/api/0/subscription/edit?client=' + SOURCE;
		
		// Instance variables	
		private var _sid:String;
		private var _auth:String;
		private var _token:String;
		private var _sessionCookie:SharedObject;

		private var authStatusMap:Dictionary;
		private var requestQueue:Dictionary;
		private var callbackQueue:Dictionary;
		private var retriedOperations:Array;
		private var xmlDecoder:SimpleXMLDecoder;

		// Callbacks
		public var onRequestSuccess:Function;
		public var onRequestError:Function;

		
		/*** INSTANCE METHODS ***/
		
		
		public function GoogleReader()
		{
			requestQueue = new Dictionary();
			callbackQueue = new Dictionary();
			retriedOperations = new Array();
			xmlDecoder = new SimpleXMLDecoder(true);
			authStatusMap = new Dictionary();
			// Initialize persistent object
			_sessionCookie = SharedObject.getLocal("session");
			// Retrieve stored credentials
			_sid = _sessionCookie.data.sid;
			_auth = _sessionCookie.data.auth;
		}

		// Queue methods to keep track of async operations on URL requests, callbacks and retried operations
		
		private function clearFromRequestQueue(urlLoader:Object):URLRequest
		{
			if (urlLoader) {
				var urlReq:URLRequest = requestQueue[urlLoader] as URLRequest;
				if (urlReq) {
					requestQueue[urlLoader] = null;
					delete requestQueue[urlLoader];
					return urlReq;
				}
			}
			return null;
		}

		
		private function clearFromCallbackQueue(urlLoader:Object):String
		{
			if (urlLoader) {
				var callback:String = callbackQueue[urlLoader] as String;
				if (callback) {
					callbackQueue[urlLoader] = null;
					delete callbackQueue[urlLoader];
					return callback;
				}
			}
			return null;
		}
		
		
		private function addToRequestQueue(request:Object, urlLoader:URLLoader):void {
			if (!(urlLoader in requestQueue)) requestQueue[urlLoader] = request;				
		}
		
		
		private function addToCallbackQueue(callback:String, urlLoader:URLLoader):void {
			if (!(urlLoader in callbackQueue)) callbackQueue[urlLoader] = callback;	
		}

		
		private function dictionaryHasValue(dic:Dictionary, val:Object):Boolean
		{
			for (var key:Object in dic)
				if (dic[key] == val)
					return true;
			return false;
		}
		
		
		private function removeItemFromArray(obj:Object, arr:Array):void 
		{
			for (var i:int = 0; i < arr.length; i++)
				if (arr[i] == obj)
					arr.splice(i, 1);
		}
		
		
		// Builds a HTTP header containing Google authorization and session cookie
		private function getAuthenticationHeaders():Array
		{
			var auth:String = "GoogleLogin auth=" + _auth;
			var cookie:String = "Name=SID;Value=" + _sid + ";Domain=.google.com;Path=/;Expires=1600000000";
			var headers:Array = new Array(new URLRequestHeader("Authorization", auth), new URLRequestHeader("Cookie", cookie));
			return headers;
		}
		
		
		public function areWeLoggedIn():Boolean {
			return (_sid == null) ? false : true ;
		}

		
		public function logout():void { 
			_sid = _auth = _token = null; 
			_sessionCookie.clear();
		}
		
		
		/*** GOOGLE READER WRAPPERS ***/
		
		
		/**
		 * Authentication request to Google.
		 * PoC: curl --data "service=reader&Email=foo@gmail.com&Passwd=f31337" https://www.google.com/accounts/ClientLogin
		 * 
		 */
		public function authenticate(email:String, password:String, callback:String):void
		{
			var authRequest:URLRequest = new URLRequest();
			authRequest.url = LOGIN_URL;
			authRequest.method = "POST";
			var variables: URLVariables = new URLVariables();
			variables.service = "reader";
			variables.source = SOURCE;
			variables.Email = email;
			variables.Passwd = password;
			authRequest.data = variables;
			
			// To avoid duplicated requests, check if a similar request is in progress
			if (dictionaryHasValue(requestQueue, authRequest)) return;
			
			var authConnection:URLLoader = new URLLoader();
			authConnection.addEventListener(Event.COMPLETE, authenticationCompleted);
			authConnection.addEventListener(IOErrorEvent.IO_ERROR, authenticationError);
			authConnection.addEventListener(HTTPStatusEvent.HTTP_STATUS, authenticationStatusEvent);
			
			authConnection.load(authRequest);
			
			addToRequestQueue(authRequest, authConnection);
			addToCallbackQueue(callback, authConnection);			
		}

		
		// Handles authentication success, storing authorization data returned by Google.
		private function authenticationCompleted(event:Event):void
		{
			// SID=2F..98\nLSID=DQAA..-3Q\nAuth=DQAA..-N8
			var result:String = String(event.target.data);
			
			// Will split keys and values, i.e. [SID, 2F..98, ..., Auth, DQAA..8F]
			var tokens:Array = result.split(/[\n=]/);
			
			// Housekeeping (remove unnecessary event listeners)
			var urlLoader:URLLoader = event.target as URLLoader;
			urlLoader.removeEventListener(Event.COMPLETE, authenticationCompleted);
			urlLoader.removeEventListener(IOErrorEvent.IO_ERROR, authenticationError);

			// Find SID and Auth values	
			for(var i:int = 0; i < tokens.length; i++) {
				if ((tokens[i] == "SID") && (i+1 != tokens.length))
					_sid = tokens[i+1];
				else if ((tokens[i] == "Auth") && (i+1 != tokens.length))
					_auth = tokens[i+1];
			}
			
			// Store session credentials
			_sessionCookie.data.sid = _sid;
			_sessionCookie.data.auth = _auth;
			_sessionCookie.flush();
			
			// Notify listener
			this.onRequestSuccess("OK", callbackQueue[urlLoader]);
			
			clearFromRequestQueue(urlLoader);
			clearFromCallbackQueue(urlLoader);
			
			// Request session token used on EDIT commands
			requestToken();
		}
		
		
		// Handles authentication error.
		private function authenticationError(event:IOErrorEvent):void
		{
			var urlLoader:URLLoader = event.target as URLLoader;
			urlLoader.removeEventListener(Event.COMPLETE, authenticationCompleted);
			urlLoader.removeEventListener(IOErrorEvent.IO_ERROR, authenticationError);

			// Google's error message
			var googleResponse:String = String(urlLoader.data);
			trace("at authenticationError = " + googleResponse);
			
			// This will be the error message to return
			var returnedMessage:String = "";
			
			if (urlLoader in authStatusMap) {
				authStatusMap[urlLoader] = null;
				delete authStatusMap[urlLoader];
				
				var errorMessage:String = googleResponse;
				var errorMsgIndex:int = googleResponse.indexOf("Error=");
				if (errorMsgIndex > -1) {
					// Find out what's the error
					errorMessage = errorMessage.substring(errorMsgIndex + 6);
					if (errorMessage == "CaptchaRequired") {
						// TODO
						// http://code.google.com/apis/accounts/docs/AuthForInstalledApps.html
						// Image is at "http://www.google.com/accounts/" + CaptchaUrl
						// Resend login including logintoken=[the CAPTCHA token];logincaptcha=[user's answer]
						// or open browser at "https://www.google.com/accounts/DisplayUnlockCaptcha"
						returnedMessage = errorMessage;
					} else if (errorMessage == "BadAuthentication") {
						returnedMessage = errorMessage;
					} else {
						returnedMessage = "AuthenticationFailed";
					}
				} else {
					// Couldn't find error message
					returnedMessage = API_ERROR;
				}
			} else {
				// Couldn't detect HTTP 403
				returnedMessage = API_ERROR;
			}
			
			this.onRequestError(returnedMessage, callbackQueue[urlLoader]);
			
			clearFromRequestQueue(urlLoader);
			clearFromCallbackQueue(urlLoader);
		}
		
		
		private function authenticationStatusEvent(event:HTTPStatusEvent):void
		{
			var urlLoader:URLLoader = event.target as URLLoader;
			urlLoader.removeEventListener(HTTPStatusEvent.HTTP_STATUS, authenticationStatusEvent);
			
			if(event.status == HTTP_STATUS_FORBIDDEN) {
				authStatusMap[urlLoader] = event.status;
			}
		}


		/**
		 * Get session token.
		 * PoC: curl --header "..." --cookie "..." http://www.google.com/reader/api/0/token
		 * 
		 */		
		private function requestToken():void
		{
			var tokenRequest:URLRequest = new URLRequest();
			tokenRequest.url = TOKEN_URL;
			tokenRequest.requestHeaders = getAuthenticationHeaders();
			
			makeRequestToGoogle(tokenRequest, "token");
		}
		
		
		/**
		 * Request a new token and retry a failed request.
		 * PoC: curl --header "..." --cookie "..." http://www.google.com/reader/api/0/token
		 * 
		 * @param failedRequest:URLRequest - request that failed due to token expiration 
		 * 
		 */		
		private function getTokenForRequest(failedRequest:URLRequest, failedCallback:String):void
		{	
			var tokenRequest:URLRequest = new URLRequest();
			tokenRequest.url = TOKEN_URL;
			tokenRequest.requestHeaders = getAuthenticationHeaders();
			
			// To avoid duplicated requests, check if a similar request is in progress
			if (dictionaryHasValue(requestQueue, tokenRequest)) return;
			
			var connection:URLLoader = new URLLoader();
			connection.addEventListener(Event.COMPLETE, tokenReceived);
			connection.addEventListener(IOErrorEvent.IO_ERROR, tokenError);			
			connection.load(tokenRequest);

			addToRequestQueue(failedRequest, connection);
			addToCallbackQueue(failedCallback, connection);
		}

		
		private function tokenReceived(event:Event):void
		{
			var urlLoader:URLLoader = event.target as URLLoader;
			urlLoader.removeEventListener(Event.COMPLETE, tokenReceived);
			urlLoader.removeEventListener(IOErrorEvent.IO_ERROR, tokenError);

			var failedRequest:URLRequest = clearFromRequestQueue(urlLoader);
			var failedCallback:String = clearFromCallbackQueue(urlLoader);				
			
			var data:String = urlLoader.data;
			
			// Tokens start with double slash, e.g. "//316lmAaPXfWzOsDJtE2qyw"
			if (data.indexOf("//") == 0) {
				// Retry operation with new token
				_token = data;
				failedRequest.data.T = _token;
				// Remember retried operation to avoid retrying more than once
				retriedOperations.push(failedRequest);
				// Repeat failed request, and if it still doesn't return OK, we need to login again
				makeRequestToGoogle(failedRequest, failedCallback);
			} else {
				this.onRequestError("NoSessionToken", failedCallback);	
			}	
		}
		
		
		private function tokenError(event:IOErrorEvent):void
		{
			var urlLoader:URLLoader = event.target as URLLoader;
			urlLoader.removeEventListener(Event.COMPLETE, tokenReceived);
			urlLoader.removeEventListener(IOErrorEvent.IO_ERROR, tokenError);

			clearFromRequestQueue(urlLoader);
			var failedCallback:String = clearFromCallbackQueue(urlLoader);				
			
			this.onRequestError("NoSessionToken", failedCallback);
		}
		
		
		/**
		 * Request user information.
		 * PoC: curl --header "..." --cookie "..." https://www.google.com/reader/api/0/user-info
		 * 
		 */		
		public function getUser(callback:String):void 
		{
			var request:URLRequest = new URLRequest();
			request.url = USERINFO_URL + '?client=' + SOURCE;
			request.requestHeaders = getAuthenticationHeaders();
			
			makeRequestToGoogle(request, callback);			
		}
		

		/**
		 * Retrieve user's subscriptions.
		 * PoC: curl --header "..." --cookie "..." http://www.google.com/reader/api/0/subscription/list
		 * 
		 */
		public function getSubscriptions(callback:String):void 
		{
			var request:URLRequest = new URLRequest();
			var timestamp:Number = (new Date()).getTime();
			request.url = SUBSCRIPTIONS_URL + '?output=json&ck=' + timestamp;
			request.requestHeaders = getAuthenticationHeaders();
			
			makeRequestToGoogle(request, callback);			
		}

		
		/**
		 * Retrieve subscription's entries.
		 * PoC: curl --header "" --cookie "" http://www.google.com/reader/atom/feed/http://feeds.bbci.co.uk/news/rss.xml?n=10
		 * 
		 * @param id:String - Subscription URL with 'feed/' prefix
		 * @param limit:Number - The number of entries to retrieve. If set to 0 or missing, Google will return all items.
		 * 
		 */		
		public function getItemsForFeed(id:String, limit:Number, callback:String):void 
		{
			var request:URLRequest = new URLRequest();
			var timestamp:Number = (new Date()).getTime();
			request.url = READER_URL + GET_ATOM + id + "?n=" + limit + '&ck=' + timestamp;
			request.requestHeaders = getAuthenticationHeaders();
			
			makeRequestToGoogle(request, callback);			
		}
		

		/**
		 * Get labeled entries.
		 * PoC: curl --header "..." --cookie "..." http://www.google.com/reader/atom/user/-/state/com.google/starred
		 * 
		 */
		public function getItemsLabeledAs(label:String, limit:Number, callback:String):void
		{
			var request:URLRequest = new URLRequest();
			var timestamp:Number = (new Date()).getTime();
			request.url = READER_URL + GET_ATOM + STATE + label + "?n=" + limit + '&ck=' + timestamp;
			request.requestHeaders = getAuthenticationHeaders();
			
			makeRequestToGoogle(request, callback);			
		}
		

		/**
		 * Tag an item with a specific label.
		 * PoC: curl -H "" --cookie "" -d "a=[STATE][TAG]&s=[SOURCE_ID]&i=[ITEM_ID]&T=[TOKEN]" [READER_URL]/api/0/edit-tag
		 * 
		 * @param tag:String - new label for item, e.g. "starred", "Tech", "read", "myLabel"
		 * @param on:Boolean - if false, label will be removed from item (i.e. item will be untagged)
		 * 
		 */	
		public function tagItem(id:String, source:String, tag:String, on:Boolean, callback:String):void
		{
			var request:URLRequest = new URLRequest();
			request.url = READER_URL + EDIT_TAG;
			request.method = "POST";
			request.requestHeaders = getAuthenticationHeaders();

			var variables:URLVariables = new URLVariables();
			if (on) 
				variables.a = STATE + tag;
			else 
				variables.r = STATE + tag;
			variables.s = source;
			variables.i = id;
			variables.T = _token;
			
			request.data = variables;
			
			makeRequestToGoogle(request, callback);
		}
		
		
		/**
		 * Edit a subscription.
		 * PoC: curl -H "." cookie "." -d "s=[FEED_ID]&ac=subscribe&T=[TOKEN]" [READER_URL]/api/0/subscription/edit
		 * 
		 * @param keep:Boolean - if true, POST variable ac = "subscribe", otherwise "unsubscribe"
		 * 
		 */			
		private function editSubscription(id:String, keep:Boolean, callback:String):void
		{
			var request:URLRequest = new URLRequest();
			request.url = READER_URL + EDIT_SUBS;
			request.method = "POST";
			request.requestHeaders = getAuthenticationHeaders();
			var variables:URLVariables = new URLVariables();
			variables.s = id;
			variables.ac = (keep) ? "subscribe" : "unsubscribe";
			variables.T = _token;
			request.data = variables;
	
			makeRequestToGoogle(request, callback);
		}

		
		public function addSubscription(url:String, callback:String):void 
		{
			// Add "feed/" prefix if needed
			if (url.indexOf("feed/") != 0) url = "feed/" + url;			
			
			editSubscription(url, true, callback);
		}
		
		
		public function delSubscription(id:String, callback:String):void {
			editSubscription(id, false, callback);
		}
		
		
		/*** GOOGLE READER REQUESTS ***/

		
		/**
		 * Handles Google's API operations.
		 * 
		 */		
		private function makeRequestToGoogle(request:URLRequest, callback:String):void
		{
			if (!areWeLoggedIn()) {
				this.onRequestError("LoginRequired", callback);
				return;
			}
			
			// To avoid duplicated requests, check if a similar request is in progress
			if (dictionaryHasValue(requestQueue, request)) return;
									
			var connection:URLLoader = new URLLoader();
			connection.addEventListener(Event.COMPLETE, gRequestCompleted);
			connection.addEventListener(IOErrorEvent.IO_ERROR, gRequestError);		
			connection.load(request);
			
			addToRequestQueue(request, connection);
			addToCallbackQueue(callback, connection);
		}


		/**
		 * Handles request success, decoding and parsing whatever Google is responding.
		 * 
		 */		
		private function gRequestCompleted(event:Event):void
		{
			var urlLoader:URLLoader = event.target as URLLoader;
			urlLoader.removeEventListener(Event.COMPLETE, gRequestCompleted);
			urlLoader.removeEventListener(IOErrorEvent.IO_ERROR, gRequestError);
			
			var command:String = (requestQueue[urlLoader] as URLRequest).url;
			var data:String = urlLoader.data;
			var resultObj:Object;
			var xmlDoc:XMLDocument;
						
			if (command.indexOf(SUBSCRIPTIONS_URL) == 0) {
				resultObj = JSON.decode(data);
			} else if (command.indexOf(READER_URL + GET_ATOM + "feed/") == 0) {				
				// command = http://www.google.com/reader/atom/feed/http://feeds.bbci.co.uk/news/rss.xml?n=10
				
				try {
					xmlDoc = new XMLDocument(data);
				} catch(err:Error) {
					xmlDoc = null;
				}
				
				if ( !xmlDoc ) {
					resultObj = { error: API_ERROR };
				} else {
					resultObj = xmlDecoder.decodeXML(xmlDoc);
				}
				
			} else if (command.indexOf(READER_URL + GET_ATOM + STATE) == 0) { 
				// command = http://www.google.com/reader/atom/user/-/state/com.google/starred
				
				try {
					xmlDoc = new XMLDocument(data);
				} catch(err:Error) {
					xmlDoc = null;
				}
				
				if ( !xmlDoc ) {
					resultObj = { error: API_ERROR };
				} else {
					resultObj = xmlDecoder.decodeXML(xmlDoc);
				}
				
			} else if (command.indexOf(READER_URL + EDIT_TAG) == 0) {
				removeItemFromArray(requestQueue[urlLoader], retriedOperations);
				resultObj = ( data == "OK" ) ? data : { error: "TagError" };
			} else if (command.indexOf(READER_URL + EDIT_SUBS) == 0) {
				removeItemFromArray(requestQueue[urlLoader], retriedOperations);
				resultObj = ( data == "OK" ) ? data : { error: "SubscriptionEditError" };
			} else if (command.indexOf(USERINFO_URL) == 0) {
				resultObj = JSON.decode(data);
			} else if (command.indexOf(TOKEN_URL) == 0) {
				if (data.indexOf("//") == 0) 
					_token = data;
				return;
			}

			// Notify listener
			this.onRequestSuccess(resultObj, callbackQueue[urlLoader]);
			
			clearFromRequestQueue(urlLoader);
			clearFromCallbackQueue(urlLoader);				
		}

		
		/**
		 * Handles request errors.
		 * 
		 */			
		private function gRequestError(event:IOErrorEvent):void
		{
			var urlLoader:URLLoader = event.target as URLLoader;
			urlLoader.removeEventListener(Event.COMPLETE, gRequestCompleted);
			urlLoader.removeEventListener(IOErrorEvent.IO_ERROR, gRequestError);
			
			// Get failed request object
			var urlRequest:URLRequest = clearFromRequestQueue(urlLoader);
			var command:String = urlRequest.url;
			var callback:String = clearFromCallbackQueue(urlLoader);
						
			var data:String = urlLoader.data;
			var error_msg:String = "";
			
			if (command.indexOf(SUBSCRIPTIONS_URL) == 0) {
				error_msg = "SubscriptionsError";
			} else if (command.indexOf(READER_URL + GET_ATOM + "feed/") == 0) {
				error_msg = "SubscriptionEntriesError";	
			} else if (command.indexOf(USERINFO_URL) == 0) {
				error_msg = "NoUserData";
			} else if (command.indexOf(TOKEN_URL) == 0) {
				error_msg = "LoginRequired";
			} else if (command.indexOf("edit") != -1) {
				// Token expiration could be the reason for failed EDIT operations (EDIT_TAG, EDIT_SUBS)
				// Try a new token and retry request once more, and if it still doesn't return OK, it's a failure.
				if (retriedOperations.indexOf(urlRequest) == -1) {
					getTokenForRequest(urlRequest, callback);
				} else {
					removeItemFromArray(urlRequest, retriedOperations);
					logout();
					error_msg = "LoginRequired";
				}				
			} else {
				error_msg = API_ERROR;
			}
			
			// Notify listener
			this.onRequestError(error_msg, callback);			
		}
		
	}
	
}