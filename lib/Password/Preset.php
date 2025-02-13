<?php
/**
 * Password_Preset
 *
 * This interface returns an array of rules for a given preset
 *
 * @author Christophe Gosiau <christophe@tigron.be>
 * @author Gerry Demaret <gerry@tigron.be>
 */

namespace Password;

interface Preset {

	/**
	 * Does the given password matches this condition
	 *
	 * @access public
	 * @return array $rules
	 */
	public static function export(): array;

}

