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

namespace Froxlor\Cron\Http;

use Froxlor\Cron\Http\Php\PhpInterface;
use Froxlor\Database\Database;
use Froxlor\FileDir;
use Froxlor\Froxlor;
use Froxlor\Http\Directory;
use Froxlor\Settings;

/**
 * @author        Froxlor team <team@froxlor.org> (2010-)
 */
class ApacheVarnish extends Apache
{

	public function createIpPort()
	{

		$ipport = 'localhost:8080';

		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'apache::createIpPort: creating ip/port settings for  ' . $ipport);
		$vhosts_filename = FileDir::makeCorrectFile(Settings::Get('system.apacheconf_vhost') . '/10_froxlor_ipandport_localhost.8080.conf');

		if (!isset($this->virtualhosts_data[$vhosts_filename])) {
			$this->virtualhosts_data[$vhosts_filename] = '';
		}

        // only set namevirtualhost for apache2.2, apache2.4 does not need this anymore 
		if (Settings::Get('system.apache24') == '0') {
			$this->virtualhosts_data[$vhosts_filename] .= 'NameVirtualHost ' . $ipport . "\n";
			FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, $ipport . ' :: inserted namevirtualhost-statement');
		}

		$without_vhost = $this->virtualhosts_data[$vhosts_filename];
		$close_vhost = true;

		$this->virtualhosts_data[$vhosts_filename] .= '<VirtualHost ' . $ipport . '>' . "\n";

		$mypath = $this->getMyPath(["docroot" => ""]);

		$this->virtualhosts_data[$vhosts_filename] .= 'DocumentRoot "' . rtrim($mypath, "/") . '"' . "\n";

		$this->virtualhosts_data[$vhosts_filename] .= ' ServerName ' . Settings::Get('system.hostname') . "\n";

		$froxlor_aliases = Settings::Get('system.froxloraliases');
		if (!empty($froxlor_aliases)) {
			$froxlor_aliases = explode(",", $froxlor_aliases);
			$aliases = "";
			foreach ($froxlor_aliases as $falias) {
				if (Validate::validateDomain(trim($falias))) {
					$aliases .= trim($falias) . " ";
				}
			}
			$aliases = trim($aliases);
			if (!empty($aliases)) {
				$this->virtualhosts_data[$vhosts_filename] .= ' ServerAlias ' . $aliases . "\n";
			}
		}

			
	    if (Settings::Get('system.froxlordirectlyviahostname')) {
	    	$relpath = "/";
	    } else {
	    	$relpath = "/" . basename(Froxlor::getInstallDir());
	    }
	    // protect lib/userdata.inc.php
	    $this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . rtrim($relpath, "/") . '/lib/">' . "\n";
	    $this->virtualhosts_data[$vhosts_filename] .= '    <Files "userdata.inc.php">' . "\n";
	    if (Settings::Get('system.apache24') == '1') {
	    	$this->virtualhosts_data[$vhosts_filename] .= '    Require all denied' . "\n";
	    } else {
	    	$this->virtualhosts_data[$vhosts_filename] .= '    Order deny,allow' . "\n";
	    	$this->virtualhosts_data[$vhosts_filename] .= '    deny from all' . "\n";
	    }
	    $this->virtualhosts_data[$vhosts_filename] .= '    </Files>' . "\n";
	    $this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";
    	// protect bin/
	    $this->virtualhosts_data[$vhosts_filename] .= '  <DirectoryMatch "^' . rtrim($relpath, "/") . '/(bin|cache|logs|tests|vendor)/">' . "\n";
	    if (Settings::Get('system.apache24') == '1') {
	    	$this->virtualhosts_data[$vhosts_filename] .= '    Require all denied' . "\n";
	    } else {
	    	$this->virtualhosts_data[$vhosts_filename] .= '    Order deny,allow' . "\n";
	    	$this->virtualhosts_data[$vhosts_filename] .= '    deny from all' . "\n";
	    }
	    $this->virtualhosts_data[$vhosts_filename] .= '  </DirectoryMatch>' . "\n";

	    // create fcgid <Directory>-Part (starter is created in apache_fcgid)
	    if (Settings::Get('system.mod_fcgid_ownvhost') == '1' && Settings::Get('system.mod_fcgid') == '1') {
            $configdir = FileDir::makeCorrectDir(Settings::Get('system.mod_fcgid_configdir') . '/froxlor.panel/' . Settings::Get('system.hostname'));
            $this->virtualhosts_data[$vhosts_filename] .= '  FcgidIdleTimeout ' . Settings::Get('system.mod_fcgid_idle_timeout') . "\n";
            if ((int)Settings::Get('system.mod_fcgid_wrapper') == 0) {
	        	$this->virtualhosts_data[$vhosts_filename] .= '  SuexecUserGroup "' . Settings::Get('system.mod_fcgid_httpuser') . '" "' . Settings::Get('system.mod_fcgid_httpgroup') . '"' . "\n";
            	$this->virtualhosts_data[$vhosts_filename] .= '  ScriptAlias /php/ ' . $configdir . "\n";
            } else {
                $domain = [
                	'id' => 'none',
        	        'domain' => Settings::Get('system.hostname'),
                    'adminid' => 1, /* first admin-user (superadmin) */
                    'mod_fcgid_starter' => -1,
		            'mod_fcgid_maxrequests' => -1,
    	            'guid' => Settings::Get('system.mod_fcgid_httpuser'),
		            'openbasedir' => 0,
    	            'email' => Settings::Get('panel.adminmail'),
    	            'loginname' => 'froxlor.panel',
    	            'documentroot' => $mypath,
    	            'customerroot' => $mypath
                ];
                $php = new PhpInterface($domain);
                $phpconfig = $php->getPhpConfig(Settings::Get('system.mod_fcgid_defaultini_ownvhost'));
                if ($phpconfig['pass_authorizationheader'] == '1') {
            	    $this->virtualhosts_data[$vhosts_filename] .= '  FcgidPassHeader     Authorization' . "\n";
                }
                $starter_filename = FileDir::makeCorrectFile($configdir . '/php-fcgi-starter');
                $this->virtualhosts_data[$vhosts_filename] .= '  SuexecUserGroup "' . Settings::Get('system.mod_fcgid_httpuser') . '" "' . Settings::Get('system.mod_fcgid_httpgroup') . '"' . "\n";
                $this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . $mypath . '">' . "\n";
                $file_extensions = explode(' ', $phpconfig['file_extensions']);
                $this->virtualhosts_data[$vhosts_filename] .= '    <FilesMatch "\.(' . implode('|', $file_extensions) . ')$">' . "\n";
                $this->virtualhosts_data[$vhosts_filename] .= '      SetHandler fcgid-script' . "\n";
                foreach ($file_extensions as $file_extension) {
                	$this->virtualhosts_data[$vhosts_filename] .= '      FcgidWrapper ' . $starter_filename . ' .' . $file_extension . "\n";
                }
				$this->virtualhosts_data[$vhosts_filename] .= '      Options +ExecCGI' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '    </FilesMatch>' . "\n";
				// >=apache-2.4 enabled?
				if (Settings::Get('system.apache24') == '1') {
					$mypath_dir = new Directory($mypath);
					// only create the require all granted if there is not active directory-protection
					// for this path, as this would be the first require and therefore grant all access
					if ($mypath_dir->isUserProtected() == false) {
						$this->virtualhosts_data[$vhosts_filename] .= '    Require all granted' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '    AllowOverride All' . "\n";
					}
				} else {
					$this->virtualhosts_data[$vhosts_filename] .= '    Order allow,deny' . "\n";
					$this->virtualhosts_data[$vhosts_filename] .= '    allow from all' . "\n";
				}
				$this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";
			}
		} elseif (Settings::Get('phpfpm.enabled') == '1' && (int)Settings::Get('phpfpm.enabled_ownvhost') == 1) {
			// get fpm config
			$fpm_sel_stmt = Database::prepare("
				SELECT f.id FROM `" . TABLE_PANEL_FPMDAEMONS . "` f
				LEFT JOIN `" . TABLE_PANEL_PHPCONFIGS . "` p ON p.fpmsettingid = f.id
				WHERE p.id = :phpconfigid
			");
			$fpm_config = Database::pexecute_first($fpm_sel_stmt, [
				'phpconfigid' => Settings::Get('phpfpm.vhost_defaultini')
			]);
			// create php-fpm <Directory>-Part (config is created in apache_fcgid)
			$domain = [
				'id' => 'none',
				'domain' => Settings::Get('system.hostname'),
				'adminid' => 1, /* first admin-user (superadmin) */
				'mod_fcgid_starter' => -1,
				'mod_fcgid_maxrequests' => -1,
				'guid' => Settings::Get('phpfpm.vhost_httpuser'),
				'openbasedir' => 0,
				'email' => Settings::Get('panel.adminmail'),
				'loginname' => 'froxlor.panel',
				'documentroot' => $mypath,
				'customerroot' => $mypath,
				'fpm_config_id' => isset($fpm_config['id']) ? $fpm_config['id'] : 1
			];

			$php = new phpinterface($domain);
			$phpconfig = $php->getPhpConfig(Settings::Get('phpfpm.vhost_defaultini'));
			$srvName = substr(md5($ipport), 0, 4) . '.fpm.external';

			// mod_proxy stuff for apache-2.4
			if (Settings::Get('system.apache24') == '1' && Settings::Get('phpfpm.use_mod_proxy') == '1') {
				$filesmatch = $phpconfig['fpm_settings']['limit_extensions'];
				$extensions = explode(" ", $filesmatch);
				$filesmatch = "";
				foreach ($extensions as $ext) {
					$filesmatch .= substr($ext, 1) . '|';
				}
				// start block, cut off last pipe and close block
				$filesmatch = '(' . str_replace(".", "\.", substr($filesmatch, 0, -1)) . ')';
				$this->virtualhosts_data[$vhosts_filename] .= '  <FilesMatch \.' . $filesmatch . '$>' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '    <If "-f %{SCRIPT_FILENAME}">' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '  	SetHandler proxy:unix:' . $php->getInterface()->getSocketFile() . '|fcgi://localhost' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '    </If>' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '  </FilesMatch>' . "\n";
				if ($phpconfig['pass_authorizationheader'] == '1') {
					$this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . $mypath . '">' . "\n";
					$this->virtualhosts_data[$vhosts_filename] .= '      CGIPassAuth On' . "\n";
					$this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";
				}
			} else {
				$addheader = "";
				if ($phpconfig['pass_authorizationheader'] == '1') {
					$addheader = " -pass-header Authorization";
				}
				$this->virtualhosts_data[$vhosts_filename] .= '  FastCgiExternalServer ' . $php->getInterface()->getAliasConfigDir() . $srvName . ' -socket ' . $php->getInterface()->getSocketFile() . ' -idle-timeout ' . $phpconfig['fpm_settings']['idle_timeout'] . $addheader . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '  <Directory "' . $mypath . '">' . "\n";
				$filesmatch = $phpconfig['fpm_settings']['limit_extensions'];
				$extensions = explode(" ", $filesmatch);
				$filesmatch = "";
				foreach ($extensions as $ext) {
					$filesmatch .= substr($ext, 1) . '|';
				}
				// start block, cut off last pipe and close block
				$filesmatch = '(' . str_replace(".", "\.", substr($filesmatch, 0, -1)) . ')';
				$this->virtualhosts_data[$vhosts_filename] .= '   <FilesMatch \.' . $filesmatch . '$>' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '     AddHandler php-fastcgi .php' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '     Action php-fastcgi /fastcgiphp' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '      Options +ExecCGI' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '    </FilesMatch>' . "\n";
				// >=apache-2.4 enabled?
				if (Settings::Get('system.apache24') == '1') {
					$mypath_dir = new Directory($mypath);
					// only create the require all granted if there is not active directory-protection
					// for this path, as this would be the first require and therefore grant all access
					if ($mypath_dir->isUserProtected() == false) {
						$this->virtualhosts_data[$vhosts_filename] .= '    Require all granted' . "\n";
						$this->virtualhosts_data[$vhosts_filename] .= '    AllowOverride All' . "\n";
					}
				} else {
					$this->virtualhosts_data[$vhosts_filename] .= '    Order allow,deny' . "\n";
					$this->virtualhosts_data[$vhosts_filename] .= '    allow from all' . "\n";
				}
				$this->virtualhosts_data[$vhosts_filename] .= '  </Directory>' . "\n";
				$this->virtualhosts_data[$vhosts_filename] .= '  Alias /fastcgiphp ' . $php->getInterface()->getAliasConfigDir() . $srvName . "\n";
			}
		}

		if ($close_vhost) {
			$this->virtualhosts_data[$vhosts_filename] .= '</VirtualHost>' . "\n";
		}
		FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_DEBUG, $ipport . ' :: inserted vhostcontainer');

		unset($vhosts_filename);
        /**
		 * bug #32
		 */
		$this->createStandardDirectoryEntry();

		/**
		 * bug #unknown-yet
		 */
		$this->createStandardErrorHandler();
	}


    protected function getVhostContent($domain, $ssl_vhost = false)
	{
		if ($ssl_vhost === true) {
			return '';
		}

		$ipportlist = 'localhost:8080';

		$vhost_content = '<VirtualHost ' . trim($ipportlist) . '>' . "\n";
		$vhost_content .= $this->getServerNames($domain);		

		// avoid using any whitespaces
		$domain['documentroot'] = trim($domain['documentroot']);

		FileDir::mkDirWithCorrectOwnership($domain['customerroot'], $domain['documentroot'], $domain['guid'], $domain['guid'], true, true);
		$vhost_content .= $this->getWebroot($domain);
		if ($this->deactivated == false) {
			$vhost_content .= $this->composePhpOptions($domain, $ssl_vhost);
			$vhost_content .= $this->getStats($domain);
		}
		$vhost_content .= $this->getLogfiles($domain);

		if ($this->deactivated == false) {
			if ($domain['specialsettings'] != '') {
				$vhost_content .= $this->processSpecialConfigTemplate($domain['specialsettings'], $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
			}

			if (Settings::Get('system.default_vhostconf') != '') {
				$vhost_content .= $this->processSpecialConfigTemplate(Settings::Get('system.default_vhostconf'), $domain, $domain['ip'], $domain['port'], $ssl_vhost) . "\n";
			}
		}
	    $vhost_content .= '</VirtualHost>' . "\n";

	    return $vhost_content;
	}

    protection function createVarnishSystemdService(){

        FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'webcache::createVarnishSystemdService: creating systemd service file');
        $varnish_systemd_service_file = FileDir::makeCorrectFile(Settings::Get('webcache.varnish_service_file'));

        // start of varnish systemd service config
        $varnish_systemd_service_data = <<<EOD
[Unit]
Description=Varnish Cache, a high-performance HTTP accelerator
Documentation=https://www.varnish-cache.org/docs/ man:varnishd
ConditionPathExists=/etc/varnish/default.vcl
            
[Service]
Type=simple
            
# Maximum number of open files (for ulimit -n)
LimitNOFILE=131072
            
# Locked shared memory - should suffice to lock the shared memory log
# (varnishd -l argument)
# Default log size is 80MB vsl + 1M vsm + header -> 82MB
# unit is bytes
LimitMEMLOCK=85983232
ExecStart=/usr/sbin/varnishd \
          -j unix,user=vcache \
          -F \
          -a uds=/var/run/varnish.sock,PROXY,user=varnish,group=varnish,mode=660 \
          -T localhost:6082 \
          -f /etc/varnish/default.vcl \
          -S /etc/varnish/secret \
          -r cc_command,vcc_allow_inline_c,vmod_path \
          -s malloc,1g \
EOD;

        if(Settings::Get('system.http2_support') == '1'){
           $varnish_systemd_service_data .= '          -p feature=+http2' . "\n";
        }

        $result_ipsandports_stmt = Database::query("SELECT * FROM `" . TABLE_PANEL_IPSANDPORTS . "` ORDER BY `ip` ASC, `port` ASC");

		while ($row_ipsandports = $result_ipsandports_stmt->fetch(PDO::FETCH_ASSOC)) {
            if ($row_ipsandports['ssl']  == '0' && $row_ipsandports['vhostcontainer'] == '1') {

                $varnish_systemd_service_data .= ' \\' . "\n";

                if (filter_var($row_ipsandports['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $ipport = '[' . $row_ipsandports['ip'] . ']:' . $row_ipsandports['port'];
                } else {
                    $ipport = $row_ipsandports['ip'] . ':' . $row_ipsandports['port'];
                }

                $varnish_systemd_service_data .= '          -a ' . "$ipport";
            }
        }

        $varnish_systemd_service_data .= <<<EOD


ExecReload=/usr/share/varnish/varnishreload
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOD;
        FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'webcache::createVarnishSystemdService: reloading systemd daemon');
		FileDir::safe_exec(escapeshellcmd('systemd reload-daemon'));
        FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'webcache::createVarnishSystemdService: restarting varnish');
		FileDir::safe_exec(escapeshellcmd(Settings::Get('webcache.varnish_reload_command')));
    }

    protection function createHitchConfig(){

        FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'webcache::createHitchConfig: creating config file');
        $hitch_config_file = FileDir::makeCorrectFile(Settings::Get('webcache.hitch_config_file'));

        $cpuCoreCount = is_file('/proc/cpuinfo') ? (preg_match_all('/^processor/m', file_get_contents('/proc/cpuinfo')) > 0 ? round(preg_match_all('/^processor/m', file_get_contents('/proc/cpuinfo')))*0.5 : '4') : '4';

        if(Settings::Get('system.http2_support') == '1'){
            $alpnHttp2 = 'h2, http/1.1';
        } else {
            $alpnHttp2 = 'http/1.1';
        }
        
        $sslVersions = Settings::Get('system.ssl_protocols');
        $sslCiphers = Settings::Get('system.ssl_cipher_list');
        $sslCipherSuites = Settings::Get('system.tlsv13_cipher_list');

        // start of hitch config
        $hitch_config_data .= <<<EOD
frontend = {
    host = "*"
    port = "443"
}
backend = "/var/run/varnish.sock"    # uds for local connection
workers = $cpuCoreCount                     # number of CPU cores

#daemon = on

# We strongly recommend you create a separate non-privileged hitch
# user and group
user = "_hitch"
group = "varnish"

# SSL Certificate directory for x509 certificates for SNI
pem-dir = "{{settings.system.customer_ssl_path}}"
pem-dir-glob = "*_fullchain.pem"
ciphers = "$sslCiphers"
ciphersuites = "$sslCipherSuites"

# Enable to let clients negotiate HTTP/2 with ALPN. (default off)
alpn-protos = "$alpnHttp2"
tls-protos = $sslVersions

# run Varnish as backend over PROXY; varnishd -a :80 -a localhost:6086,PROXY ..
write-proxy-v2 = on             # Write PROXY header
EOD;

        FroxlorLogger::getInstanceOf()->logAction(FroxlorLogger::CRON_ACTION, LOG_INFO, 'webcache::createHitchConfig: restarting hitch');
		FileDir::safe_exec(escapeshellcmd(Settings::Get('webcache.hitch_reload_command')));
    }

}