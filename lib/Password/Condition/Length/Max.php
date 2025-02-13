<?php
/**
 * Condition max length
 *
 * This rule checks the maximum length
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition\Length;

class Max implements \Password\Condition {

	/**
	 * @var int $max_length
	 * @access private
	 */
	private ?int $max_length = null;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param int $max_length
	 */
	public function __construct($max_length) {
		$this->max_length = $max_length;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		if (strlen($password) <= $this->max_length) {
			return true;
		}
		return false;
	}

}

