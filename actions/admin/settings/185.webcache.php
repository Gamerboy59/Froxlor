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

return [
	'groups' => [
		'webcache' => [
			'title' => lng('admin.webcache_settings'),
			'icon' => 'fa-solid fa-database',
			'fields' => [
                'webcache_activated' => [
					'label' => lng('webcache.activated'),
					'settinggroup' => 'webcache',
					'varname' => 'activated',
					'type' => 'checkbox',
					'default' => true,
                    'overview_option' => true,
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['http'],
					'websrv_avail' => [
						'apache2'
					]
				],
				'webcache_varnish_config_dir' => [
					'label' => lng('webcache.varnish_config_dir'),
					'settinggroup' => 'webcache',
					'varname' => 'varnish_config_dir',
					'type' => 'text',
					'string_type' => 'filedir',
					'default' => '/etc/varnish/',
					'save_method' => 'storeSettingFieldInsertAntispamTask',
					'requires_reconf' => ['webcache']
				],
                'webcache_varnish_service_file' => [
					'label' => lng('webcache.varnish_service_file'),
					'settinggroup' => 'webcache',
					'varname' => 'varnish_service_file',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/etc/systemd/system/varnish.service',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['webcache']
				],
				'webcache_varnish_config_file' => [
					'label' => lng('webcache.varnish_config_file'),
					'settinggroup' => 'webcache',
					'varname' => 'varnish_config_file',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/etc/varnish/default.vcl',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['webcache']
				],
				'webcache_varnish_reload_command' => [
					'label' => lng('webcache.varnish_reload_command'),
					'settinggroup' => 'webcache',
					'varname' => 'varnish_reload_command',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => 'service varnish restart',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
				'webcache_varnish_restart_command' => [
					'label' => lng('webcache.varnish_restart_command'),
					'settinggroup' => 'webcache',
					'varname' => 'varnish_restart_command',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => 'service varnish restart',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				],
                'webcache_hitch_config_file' => [
					'label' => lng('webcache.hitch_config_file'),
					'settinggroup' => 'webcache',
					'varname' => 'hitch_config_file',
					'type' => 'text',
					'string_type' => 'file',
					'default' => '/etc/hitch/hitch.conf',
					'save_method' => 'storeSettingField',
					'requires_reconf' => ['webcache']
				],
                'webcache_hitch_reload_command' => [
					'label' => lng('webcache.hitch_reload_command'),
					'settinggroup' => 'webcache',
					'varname' => 'hitch_reload_command',
					'type' => 'text',
					'string_regexp' => '/^[a-z0-9\/\._\- ]+$/i',
					'default' => 'service hitch restart',
					'save_method' => 'storeSettingField',
					'required_otp' => true
				]
			]
		]
	]
];