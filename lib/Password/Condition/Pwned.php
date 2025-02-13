<?php
/**
 * Condition symbol
 *
 * This rule checks if a password contains a symbol
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition;

class Pwned implements \Password\Condition {

	/**
	 * @var bool $has_symbol
	 * @access private
	 */
	private ?int $occurences = null;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param bool $has_symbol
	 */
	public function __construct(?int $occurences = null) {
		$this->occurences = $occurences;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		$hash = sha1($password);
		$first5 = substr($hash, 0, 5);
		$rest = substr($hash, 5);
		$list = file_get_contents('https://api.pwnedpasswords.com/range/' . $first5);
		$haveMatch = preg_match('@(' . $rest . '):(\d+)*@im', $list, $matches);
		if (!$haveMatch) {
			return false;
		}

		if ($this->occurences === null) {
			return true;
		}
		$pwned = $matches[2];

		if ($this->occurences > $pwned) {
			return false;
		}

		return true;		
	}

}

