<?php

/**
 * This file is part of the Froxlor project.
 * Copyright (c) 2010 the Froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can also view it online at
 * https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  the authors
 * @author     Froxlor team <team@froxlor.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 */

use Froxlor\Install\Update;

$preconfig = [
	'title' => '2.2.x updates',
	'fields' => []
];
$return = [];

if (Update::versionInUpdate($current_version, '2.2.0-dev1')) {
	$has_preconfig = true;
	$description = 'Froxlor now features antispam configurations using rspamd. Would you like to enable the antispam feature (required re-configuration of services)?';
	$question = '<strong>Enable antispam (recommended)</strong>&nbsp;';
	$return['antispam_activated'] = [
		'type' => 'checkbox',
		'value' => 1,
		'checked' => 0,
		'label' => $question,
		'prior_infotext' => $description
	];
}
if (Update::versionInUpdate($current_db_version, '202405210')) {
    $has_preconfig = true;
    $description = 'roxlor now features webcaching configurations using varnish. Would you like to enable the wecache feature (required re-configuration of services)?';
    $question = '<strong>Enable webcache via varnish (default: no)</strong>&nbsp;';
    $return['webcache_activated'] = [
        'type' => 'checkbox',
        'value' => 1,
        'checked' => 0,
        'label' => $question,
        'prior_infotext' => $description
    ];
}

$preconfig['fields'] = $return;
return $preconfig;