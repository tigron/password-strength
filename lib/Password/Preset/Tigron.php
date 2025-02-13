<?php
/**
 * Password_Preset Tigron
 *
 * This interface returns an array of rules that are used as company-wide
 * password policy for Tigron
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password\Preset;

class Tigron {

	/**
	 * Does the given password matches this condition
	 *
	 * @access public
	 * @return array $rules
	 */
	public static function export(): array {
		$rules = [];

		$rules = array_merge($rules, \Password\Preset\Hive2024::export());
		$rules = array_merge($rules, \Password\Preset\Zxcvbn::export());

		return $rules;
	}

}

