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

class Entropy implements \Password\Condition {

	/**
	 * @var bool $has_lowercase
	 * @access private
	 */
	private ?int $score = null;

	/**
	 * Symbols
	 */
	private string $symbols = ' !"#$%&\'()*+,-./:;<=>?@[\]^_{|}~';

	/**
	 * Lowercase
	 */
	private string $lowercase = 'abcdefghijklmnopqrstuvwxyz';

	/**
	 * Uppsercase
	 */
	private string $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

	/**
	 * Numbers
	 */
	private string $numbers = '0123456789';

	/**
	 * Max occurences
	 */
	private int $max_occurences = 2;	

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
		$score = $this->get_score($password);
		if ($score === $this->score) {
			return true;
		}
		return false;
	}

	/**
	 * Get score based on entropy:
	 * 100 - 120 => STRONG
	 * 80 - 100 => GOOD
	 * 70 - 80 => ACCEPTABLE
	 * 60 - 70  => INSECURE
	 * 0 - 60 => VULNERABLE
	 *
	 * @access private
	 * @param string $password
	 * @return int $score
	 */
	private function get_score($password): int {
		$entropy = $this->get_entropy($password);
		if ($entropy <= 60) {
			return 1;
		}
		if ($entropy <= 70) {
			return 2;
		}
		if ($entropy <= 80) {
			return 3;
		}
		if ($entropy <= 90) {
			return 4;
		}		
		
		return 5;	
	}

   /**
	 * get the calculated entropy of the password based on the rules for 
	 * excluding duplicate characters
	 *
	 * @param string $password
	 * @return float
	 */
	private function get_entropy(string $password): float {
		$base = $this->get_base($password);
		$length = $this->get_length($password);

		return number_format(log($base ** $length), 0);
	}

	/**
	 * Get the base amount of characters from the characters used in the 
	 * password.
	 * This is the number of possible characters to pick from in the used 
	 * character sets e.g. 26 for only lower case passwords
	 *
	 * @param $password
	 * @return int
	 */
	public function get_base(string $password): int {
		$characters = str_split($password);
		$base = 0;
		$has_symbol = false;
		$has_lower = false;
		$has_upper = false;
		$has_number = false;

		foreach ($characters as $character) {
			if (!$has_lower && strpos($this->lowercase, $character) !== false) {
				$has_lower = true;
				$base += strlen($this->lowercase);
			}
			if (!$has_upper && strpos($this->uppercase, $character) !== false) {
				$has_upper = true;
				$base += strlen($this->uppercase);
			}
			if (!$has_symbol && strpos($this->symbols, $character) !== false) {
				$has_symbol = true;
				$base += strlen($this->symbols);
			}
			if (!$has_number && strpos($this->numbers, $character) !== false) {
				$has_number = true;
				$base += strlen($this->numbers);
			}

			if (
				strpos($this->lowercase, $character) === false
				&& strpos($this->uppercase, $character) === false
				&& strpos($this->symbols, $character) === false
				&& strpos($this->numbers, $character) === false
			) {
				$base++;
			}
		}

		return $base;
	}	

	/**
	 * Check the length of the password based on known rules
	 * Characters will only be counted a maximum of 2 times 
	 * e.g. aaa has length 2
	 *
	 * @param $password
	 * @return int
	 */
	public function get_length(string $password): int {
		$used_characters = [];
		$characters = str_split($password);
		$length = 0;

		foreach ($characters as $character) {
			if (
				array_key_exists($character, $used_characters) 
				&& $used_characters[$character] < $this->max_occurences
			) {
				$length++;
				$used_characters[$character]++;
			}
			if (!array_key_exists($character, $used_characters)) {
				$used_characters[$character] = 1;
				$length++;
			}
		}

		return $length;
	}
}

