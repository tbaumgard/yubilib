<?php

/**
 * Contains the yubilib::badRequestException class definition.
 *
 * @file
 * @copyright (c) 2016-2017 Tim Baumgard
 */

namespace yubilib;

/**
 * @addtogroup exceptions
 * @{
 */

/**
 * Exception for a bad request sent to a remote validation server.
 */
class badRequestException extends namespace\exception {

	private $response;

	/**
	 * Construct a new exception for a bad request.
	 *
	 * @param $response
	 *   server response associated with the request as a string or @c null if
	 *   it's not available
	 * @param $previousException
	 *   previous exception for exception chaining
	 */
	public function __construct($response, $previousException=null) {
		$this->response = \is_string($response) ? $response : null;

		parent::__construct("", 0, $previousException);
	}

	/**
	 * Get the response associated with the request.
	 *
	 * @return
	 *   response as a string or @c null if it wasn't available
	 */
	public function response() {
		return $this->response;
	}

}

/** @} */
