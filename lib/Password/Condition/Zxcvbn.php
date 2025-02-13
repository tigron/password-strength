<?php
/**
 * Condition Zxcvbn
 *
 * This rule checks the given password for its Zxcvbn-score
 * More information can be found here:
 * https://github.com/bjeavons/zxcvbn-php
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Condition;

class Zxcvbn implements \Password\Condition {

	/**
	 * @var bool $has_lowercase
	 * @access private
	 */
	private ?int $score = null;

	/**
	 * Constructor
	 *
	 * @access public
	 * @param bool $has_lowercase
	 */
	public function __construct($score) {
		$this->score = $score;
	}

	/**
	 * Does the given password matches this rule
	 *
	 * @access public
	 * @param string $password
	 * @return bool $matches
	 */
	public function matches($password): bool {
		$zxcvbn = new \ZxcvbnPhp\Zxcvbn();
		$result = $zxcvbn->passwordStrength($password);
		if ($result['score'] === $this->score) {
			return true;
		}
		return false;
	}

}

