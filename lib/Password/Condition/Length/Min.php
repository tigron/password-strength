<?php
/**
 * Condition max length
 *
 * This rule checks the minimum length
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition\Length;

class Min implements \Password\Condition {

	/**
	 * @var int $min_length
	 * @access private
	 */
	private ?int $min_length = null;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param bool $has_lowercase
	 */
	public function __construct($min_length) {
		$this->min_length = $min_length;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		if (strlen($password) >= $this->min_length) {
			return true;
		}
		return false;
	}

}

