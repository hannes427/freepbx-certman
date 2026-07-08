<?php
// vim: set ai ts=4 sw=4 ft=php:
//	License for all code of this FreePBX module can be found in the license file inside the module directory
//	Copyright 2014 Schmooze Com Inc.
//	Copyright 2018 Sangoma Technologies.
namespace FreePBX\modules;

include_once __DIR__."/vendor/autoload.php";

use Composer\CaBundle\CaBundle;
use BMO;
use PDO;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use Exception;

#[\AllowDynamicProperties]
class Certman extends \FreePBX_Helpers implements BMO {
	/* Asterisk Defaults */
	private $defaults = array(
		"sip" => array(
			"dtlsenable" => "no",
			"dtlsverify" => "fingerprint",
			"dtlscertfile" => "",
			"dtlscafile" => "",
			"dtlssetup" => "actpass",
			"dtlsrekey" => "0"
		),
		"pjsip" => array(
			"media_encryption" => "dtls",
			"dtls_verify" => "fingerprint",
			"dtls_cert_file" => "",
			"dtls_ca_file" => "",
			"dtls_setup" => "actpass",
			"dtls_rekey" => "0"
		)
	);
	private $message = "";

	public function __construct($freepbx = null) {
		if ($freepbx == null){
			throw new Exception("Not given a FreePBX Object");
		}
		$this->FreePBX = $freepbx;
		$this->db = $freepbx->Database;
		$this->FreePBX->PJSip = $this->FreePBX->Core->getDriver('pjsip');
		$this->PKCS = $this->FreePBX->PKCS;
		$this->PKCS->timeout = 240; //because of piiiiiis
		$this->days_expiration_alert = $this->FreePBX->Config->get("CERT_DAYS_EXPIRATION_ALERT");
	}

	public function setDatabase($pdo){
		$this->db = $pdo;
		return $this;
	}

	public function resetDatabase(){
		$this->db = $this->FreePBX->Database;
	}

	/**
	 * Used to setup the database
	 */
	public function install() {
		$certs = $this->getAllManagedCertificates();
		if(empty($certs)) {
			out(_("No Certificates exist"));

			if(!$this->checkCAexists()) {
				outn(_("Generating default CA..."));
				$hostname = gethostname();
				$hostname = !empty($hostname) ? $hostname : 'localhost';
				$caid = $this->generateCA('ca', $hostname, $hostname);
				out(_("Done!"));
			} else {
				$dat = $this->getAllManagedCAs();
				$caid = $dat[0]['uid'];
			}

			outn(_("Generating default certificate..."));
			// Do not i18n the NAME of the cert, it is 'default'.
			try {
				$cid = $this->generateCertificate($caid,"default",_("Default Self-Signed certificate"));
				$this->makeCertDefault($cid);
				out(_("Done!"));
			} catch(Exception $e) {
				out(sprintf(_("Failed! [%s]"),$e->getMessage()));
				//return false;
			}
		}
		$this->updateDefault();
		return true;
	}

	public function uninstall() {
		try {
			$this->removeCSR();
			$this->removeCA();
			$this->removeCronJob();
			$certs = $this->getAllManagedCertificates();
			foreach($certs as $cert) {
				$this->removeCertificate($cert['cid']);
			}
		} catch(Exception $e) {}

		$sql = "DROP TABLE certman_mapping";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$sql = "DROP TABLE certman_certs";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$sql = "DROP TABLE certman_cas";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		return true;
	}

	public function removeCronJob() {
		foreach($this->FreePBX->Cron()->getAll() as $cron) {
			$str = "fwconsole certificates updateall -q";
			if (preg_match("/".$str."/i",$cron,$matches)) {
				$this->FreePBX->Cron()->remove($cron);
			}
			$str = "fwconsole certificates --updateall -q";
			if (preg_match("/".$str."/i",$cron,$matches)) {
				$this->FreePBX->Cron()->remove($cron);
			}
		}
	}

	public function doConfigPageInit($page){
		$request = $_REQUEST;
		$request['certaction'] = !empty($request['certaction']) ? $request['certaction'] : "";
		switch($request['certaction']) {
			case "importlocally":
				$processed = $this->importLocalCertificates();
				if(!empty($processed)) {
					$status = '';
					foreach($processed as $p) {
						if(!$p['status']) {
							$status .= $p['file'].": ".$p['error'] . "</br>";
						}
					}
					if(!empty($status)) {
						$this->message = array('type' => 'danger', 'message' => $status);
					} else {
						$this->message = array('type' => 'success', 'message' => _("Successfully imported certificates"));
					}
				} else {
					$this->message = array('type' => 'info', 'message' => _("No certificates to import"));
				}
			break;
			case "edit":
				switch($request['type']) {
					case "up":
						$cert = $this->getCertificateDetails($_POST['cid']);
						if(!empty($cert)) {
							$name = $cert['basename'];
							$removeCSR = false;
							if(empty($_POST['privatekey']) && !empty($_POST['csrref'])) {
								$csr = $this->getCSRDetails($_POST['csrref']);
								if(empty($csr['files']['key'])) {
									//corruption
									$this->removeCSR();
									$this->message = array('type' => 'danger', 'message' => _('No Private key to reference. Try generating a CSR first.'));
									break 2;
								}
								$pkey = file_get_contents($csr['files']['key']);
								$removeCSR = true;
							} elseif(!empty($_POST['privatekey'])) {
								$pkey = $_POST['privatekey'];
							} else {
								if(empty($cert['files']['key'])) {
									$this->message = array('type' => 'danger', 'message' => _('No Private key to reference.'));
									break 2;
								}
								$pkey = file_get_contents($cert['files']['key']);
							}

							try {
								$status = $this->importCertificate($name,$pkey,$_POST['signedcert'],$_POST['certchain'],$_POST['passphrase']);
							} catch(Exception $e) {
								$this->message = array('type' => 'danger', 'message' => sprintf(_('There was an error importing the certificate: %s'),$e->getMessage()));
								break;
							}

							$this->updateCertificate($cert,$_POST['description']);
							if($removeCSR) {
								$this->removeCSR(true);
							}
							needreload();
							$this->message = array('type' => 'success', 'message' => _('Updated certificate'));
						}
					break;
					case "le":
						$errors = [];
						$cert = $this->getCertificateDetails($_POST['cid']);
						$host = $cert['basename'];
						$description = $host;
						$san = array_unique(array_filter(array_map('trim', explode("\n", strtolower($_POST['SAN'] ?? '')))));
						$challengetype = $_POST['challengetype'] ?? '';
						$dnsprovider = trim($_POST['dnsprovider'] ?? '');
						$dnsKeys = $_POST['dnsKeys'] ?? [];
						$dnsValues = $_POST['dnsValues'] ?? [];
						if (!empty($san)) {
							if (($key = array_search($host, $san, true)) !== false) {
								unset($san[$key]);
							}
							sort($san);
							foreach($san AS $tmp) {
								if(!filter_var($tmp, FILTER_VALIDATE_DOMAIN)) {
									$errors[] = _('Invalid Alternative name ' . htmlspecialchars($tmp));
								}
							}
							$description .= ", " . implode(", ", $san);
						}
						
						if(!in_array($challengetype, ['dns01', 'http01'], true)) {
							$errors[] = _('Invalid challenge type');
						}
						if($challengetype === 'dns01') {
							if(empty($dnsprovider)) {
								$errors[] = _('DNS provider may not be empty');
							}
							elseif(!preg_match('/^dns_[a-z0-9]{2,}$/', $dnsprovider)) {
								$errors[] = _('Invalid DNS provider');
							}
							if(count($dnsKeys) !== count($dnsValues)) {
    							$errors[] = _('DNS API credentials are inconsistent');
							}
							foreach($dnsKeys AS $key => $value) {
								$value = trim($value);
								$dnsKeys[$key] = $value;
								if($value === '') {
									$errors[] = _('DNS API Key may not be empty');
								}
								elseif(!preg_match('/^[A-Za-z][A-Za-z0-9_]{1,63}$/', $value)) {
									$errors[] = _('Invalid DNS API Key' . htmlspecialchars($value));
								}
							}
							foreach($dnsValues AS $key => $value) {
								$value = trim($value);
								$dnsValues[$key] = $value;
								/**
								 * The content of the API key cannot be strictly validated, as different
								 * providers may also use special characters or “dangerous” characters
								 * in their credentials. Only a limited set of characters can be checked
								 */
								if(!preg_match('/^[^\r\n\0]*$/', $value)) {
									$errors[] = _('Invalid character in DNS Api credential value');
								}
							}
						}

						$additional = [];
						if(!empty($cert)) {
							$additional = array(
								'challengetype' => $challengetype,
								'dnsprovider' => $dnsprovider,
							);
							$dnsCredentialsChanged = false;
							if (isset($_POST['dnsedit'])) {
								$dnsCredentialsChanged = true;
							}
							if (!empty($san)) {$additional['san'] = $san;}
							// check cert expiration
							$validTo = $cert['info']['crt']['validTo_time_t'];
							$renewafter = $validTo-(86400*$this->days_expiration_alert);
							$update = false;
							if(time() > $validTo) {
								$update = true;
							}
							$certAdditional = $cert['additional'];
							$isDifferent = false;
							$keysToCompare = ['challengetype', 'dnsprovider', 'san'];
							foreach ($keysToCompare as $key) {
								$v1 = $additional[$key] ?? ($key === 'san' ? [] : '');
								$v2 = $certAdditional[$key] ?? ($key === 'san' ? [] : '');
								if ($v1 !== $v2) {
									$isDifferent = true;
									break;
								}
							}

							if (!$isDifferent && !$update && !$dnsCredentialsChanged) {
								$this->message = array('type' => 'success', 'message' => _('Nothing to do, no changes made'));
								break;
							}
							if (!empty($errors)) {
        						$this->message = ['type' => 'danger','message' => implode("<br>", $errors)];
        						break;
    						}
							ob_start();
							try {
								$this->updateLE($host, $additional, $dnsKeys, $dnsValues, $dnsCredentialsChanged, false, true);
							} catch(Exception $e) {
								$lelog = trim(ob_get_contents());
								ob_end_clean();
								$einfo = json_decode($e->getMessage(), true);
								if (!is_array($einfo)) {
    								$einfo = [];
								}
								$api = $this->getFirewallAPI();
								$leoptions = $api->getLeOptions();
								if (!empty($einfo['detail'])) {
									$emessage = $einfo['detail'];
								} else {
									$emessage = $e->getMessage();
									$lelog = $lelog == ''?'': $lelog;
								}

								$hints = !empty($einfo['hints']) ? array_merge($einfo['hints'], $leoptions['hints']) : $leoptions['hints'];
								$this->message = array(	'title' => 'LetsEncrypt Update Failure',
											'type' => 'danger',
											'message' => $emessage,
											'log' => $lelog,
											'hints' => $hints,
										);
								break;
							}
							$lelog = ob_get_contents();
							ob_end_clean();
							$this->updateCertificate($cert, $description, $additional);
							$this->message = array('type' => 'success', 'title' => _('LetsEncrypt Update Success!'), 'log' => $lelog );
							needreload();
							// Reload HAProxy
							$this->reloadHAProxyIfEnabled();
						} else {
							$this->message = array('type' => 'danger', 'message' => _('Certificate is invalid'));
						}
					break;
					case "ss":
						$cert = $this->getCertificateDetails($_POST['cid']);
						if(!empty($cert)) {
							$this->updateCertificate($cert,$_POST['description']);
							$this->message = array('type' => 'success', 'message' => _('Updated certificate'));
							needreload();
						} else {
							$this->message = array('type' => 'danger', 'message' => _('Certificate is invalid'));
						}
					break;
				}
			break;
			case "add":
				switch($request['type']) {
					case "le":
						$errors = [];
						$host = trim(strtolower($_POST['host'] ?? ''));
						$san = array_unique(array_filter(array_map('trim', explode("\n", strtolower($_POST['SAN'] ?? '')))));
						$challengetype = $_POST['challengetype'] ?? '';
						$dnsprovider = trim($_POST['dnsprovider'] ?? '');
						$dnsKeys = $_POST['dnsKeys'] ?? [];
						$dnsValues = $_POST['dnsValues'] ?? [];
						if(!filter_var($host, FILTER_VALIDATE_DOMAIN)) {
							$errors[] = _('Invalid hostname');
						}
						$description = $host;
						if (!empty($san)) {
							if (($key = array_search($host, $san, true)) !== false) {
								unset($san[$key]);
							}
							sort($san);
							foreach($san AS $tmp) {
								if(!filter_var($tmp, FILTER_VALIDATE_DOMAIN)) {
									$errors[] = _('Invalid Alternative name ' . htmlspecialchars($tmp));
								}
							}
							$description .= ", " . implode(", ", $san);
						}
						$additional = [];
						if(!in_array($challengetype, ['dns01', 'http01'], true)) {
							$errors[] = _('Invalid challenge type');
						}
						if($challengetype === 'dns01') {
							if(empty($dnsprovider)) {
								$errors[] = _('DNS provider may not be empty');
							}
							elseif(!preg_match('/^dns_[a-z0-9]{2,}$/', $dnsprovider)) {
								$errors[] = _('Invalid DNS provider');
							}
							if(count($dnsKeys) !== count($dnsValues)) {
    							$errors[] = _('DNS API credentials are inconsistent');
							}
							foreach($dnsKeys AS $key => $value) {
								$value = trim($value);
								$dnsKeys[$key] = $value;
								if($value === '') {
									$errors[] = _('DNS API Key may not be empty');
								}
								elseif(!preg_match('/^[A-Za-z][A-Za-z0-9_]{1,63}$/', $value)) {
									$errors[] = _('Invalid DNS API Key' . htmlspecialchars($value));
								}
							}
							foreach($dnsValues AS $key => $value) {
								$value = trim($value);
								$dnsValues[$key] = $value;
								/**
								 * The content of the API key cannot be strictly validated, as different
								 * providers may also use special characters or “dangerous” characters
								 * in their credentials. Only a limited set of characters can be checked
								 */
								if(!preg_match('/^[^\r\n\0]*$/', $value)) {
									$errors[] = _('Invalid character in DNS Api credential value');
								}
							}
						}
						$additional = array(
								'challengetype' => $challengetype,
								'dnsprovider' => $dnsprovider,
						);
						if (!empty($san)) {$additional['san'] = $san;}
						if (!empty($errors)) {
        					$this->message = ['type' => 'danger','message' => implode("<br>", $errors)];
        					break;
    					}
						ob_start();
						try{
							if($this->checkCertificateName($host)) {
								throw new Exception(sprintf(_("%s already exists!"),$host));
							}
							$this->updateLE($host, $additional, $dnsKeys, $dnsValues,);
							$this->saveCertificate(null, $host, $description, 'le', $additional);
						} catch(Exception $e) {
							$lelog = trim(ob_get_contents());
							ob_end_clean();
							$einfo = json_decode($e->getMessage(), true);
							if (!is_array($einfo)) {
    							$einfo = [];
							}
							$api = $this->getFirewallAPI();
							$leoptions = $api->getLeOptions();
							if (!empty($einfo['detail'])) {
								$emessage = $einfo['detail'];
							} else {
								$emessage = $e->getMessage();
								$lelog = $lelog == ''?'': $lelog;
							}
							$hints = !empty($einfo['hints']) ? array_merge($einfo['hints'], $leoptions['hints']) : $leoptions['hints'];
							$this->message = array(	'title' => 'LetsEncrypt Generation Failure',
										'type' => 'danger',
										'message' => $emessage,
										'log' => $lelog,
										'hints' => $hints,
									);

						break 2;
						}
						$lelog = ob_get_contents();
						ob_end_clean();
						$this->message = array('type' => 'success', 'title' => _('LetsEncrypt Generation Success!'), 'log' => $lelog );
						$this->addAutoUpdateCron();
					break;
					case "up":
						$name = basename($_POST['name']);
						if($this->checkCertificateName($name)) {
							$this->message = array('type' => 'danger', 'message' => _('Certificate name is already in use'));
							break;
						}
						$removeCSR = false;
						if(empty($_POST['privatekey']) && !empty($_POST['csrref'])) {
							$csr = $this->getCSRDetails($_POST['csrref']);
							if(empty($csr['files']['key'])) {
								//corruption
								$this->removeCSR();
								$this->message = array('type' => 'danger', 'message' => _('No Private key to reference. Try generating a CSR first.'));
								break;
							}
							$pkey = file_get_contents($csr['files']['key']);
							$removeCSR = true;
						} elseif(!empty($_POST['privatekey'])) {
							$pkey = $_POST['privatekey'];
						} else {
							$this->message = array('type' => 'danger', 'message' => _('No Private key to reference. Try generating a CSR first.'));
							break;
						}
						try {
							$status = $this->importCertificate($name,$pkey,$_POST['signedcert'],$_POST['certchain'],$_POST['passphrase']);
							$this->saveCertificate(null,$name,$_POST['description'],'up');
						} catch(Exception $e) {
							$this->message = array('type' => 'danger', 'message' => sprintf(_('There was an error importing the certificate: %s'),$e->getMessage()));
							break;
						}
						if($removeCSR) {
							$this->removeCSR(true);
						}
						$this->message = array('type' => 'success', 'message' => _('Added new certificate'));
					break;
					case "ss":
						if(empty($request['caid'])) {
							//generate new cert authority
							$this->generateConfig('ca',$request['hostname'],$request['orgname']);
							$caid = $this->generateCA('ca',$request['hostname'],$request['orgname']);
							if(empty($caid)) {
								$this->message = array('type' => 'danger', 'message' => _('Unable to generate Certificate Authority'));
								break;
							}
						} else {
							//get old cert authority
							$dat = $this->getAllManagedCAs();
							if(empty($dat[0]['uid'])) {
								$this->message = array('type' => 'danger', 'message' => _('Unable to find Certificate Authority'));
								break;
							}
							$caid = $dat[0]['uid'];
						}
						try {
							$this->generateCertificate($caid,$request['hostname'],$request['description']);
						} catch(Exception $e) {
							$this->message = array('type' => 'danger', 'message' => sprintf(_('Unable to generate certificate: %s'),$e->getMessage()));
							break;
						}
						$this->message = array('type' => 'success', 'message' => _('Added new certificate'));
					break;
					case "csr":
						$location = $this->PKCS->getKeysLocation();
						$name = basename($_POST['name']);
						if($this->checkCertificateName($name) || $this->checkCSRName($name)) {
							$this->message = array('type' => 'danger', 'message' => _('Certificate name is already in use'));
							break 2;
						}
						$valid = array("CN","O","OU","C","ST","L");
						$params = array();
						foreach($_POST as $key => $value) {
							if(in_array($key,$valid)) {
								$params[$key] = $value;
							}
						}
						try {
							$this->PKCS->createCSR($name, $params);
							$this->saveCSR($name);
						} catch(Exception $e) {
							$this->message = array('type' => 'danger', 'message' => sprintf(_('Unable to create CSR: %s'),$e->getMessage()));
							break;
						}
						$this->message = array('type' => 'success', 'message' => _('Added new certificate signing request'));
					break;
				}
			break;
			case "delete":
				switch($request['type']) {
					case 'ca':
						$status = $this->removeCA();
						if($status) {
							$this->message = array('type' => 'success', 'message' => _('Successfully deleted the Certificate Authority'));
						} else {
							$this->message = array('type' => 'danger', 'message' => _('Unable to remove the Certificate Authority'));
						}
					break;
					case 'csr':
						$status = $this->removeCSR(true);
						if($status) {
							$this->message = array('type' => 'success', 'message' => _('Successfully deleted the Certificate Signing Request'));
						} else {
							$this->message = array('type' => 'danger', 'message' => _('Unable to remove the Certificate Signing Request'));
						}
					break;
					case 'cert':
						$cert = $this->getCertificateDetails($_REQUEST['id']);
						if(empty($cert)) {
							$this->message = array('type' => 'danger', 'message' => _('Invalid Certificate'));
							break;
						}
						$this->removeCertificate($cert['cid']);
						$this->message = array('type' => 'success', 'message' => _('Deleted Certificate'));
					break;
				}
			break;
		}
		if(isset($request['acmesettings'])) {
			//Save ACME settings
			$acmeBinary = trim($request['acmeBinary'] ?? '');
			$acmeConfDir = trim($request['acmeConfDir'] ?? '');
			$acmeEmail = trim($request['acmeEmail'] ?? '');
			$acmeUpdateMethod = trim($request['acmeUpdateMethod'] ?? '');

			//Validation
			$error = false;
			$errors[] = _('Could not save ACME configuration. The following errors occurred');
			//ACME script path
			if(!preg_match('/^\/[A-Za-z0-9\._\-\/]+\/acme\.sh$/', $acmeBinary)) {
				$errors[] = _('Invalid acme.sh binary path');
				$error = true ;
			}
			if(!is_file($acmeBinary)) {
				$errors[] = _('acme.sh binary does not exist');
				$error = true ;
			}
			if(!is_executable($acmeBinary)) {
				$errors[] = _('acme.sh is not executable');
				$error = true;
			}
			//ACME Config dir
			if(!preg_match('#^/[A-Za-z0-9._/-]+$#', $acmeConfDir)) {
				$errors[] = _('Invalid ACME configuration path');
				$error = true ;
			}
			if(is_dir($acmeConfDir)) {
				if (!is_writable($acmeConfDir)) {
					$errors[] = _('ACME configuration directory is not writable');
					$error = true;
				}
			}
			else {
				$parent = dirname($acmeConfDir);
				if(is_dir($parent) && !is_writable($parent)) {
					$errors[] = _('ACME configuration directory is not writable');
					$error = true;
				}
			}
			//ACME eMail
			if($acmeEmail !== '' && !filter_var($acmeEmail, FILTER_VALIDATE_EMAIL)) {
				$errors[] = _('Invalid ACME eMail address');
				$error = true ;
			}
			//ACME Update Method
			if(!in_array($acmeUpdateMethod, ['cron', 'freepbx'], true)) {
				$errors[] = _('Invalid Certificate renew mechanism');
				$error = true ;
			}
			if($error) {
				$this->message = array('type' => 'danger', 'message' => implode("<br>", array_map('htmlspecialchars', $errors)));
				return ;
			} else {
				if(!is_dir($acmeConfDir)) {
					if(!@mkdir($acmeConfDir, 0700, true)) {
						$this->message = array('type' => 'danger', 'message' => _('Failed to create configuration directory'));
						return ;
					}
				}
				$set_ca = exec(escapeshellarg($acmeBinary) . " --config-home " . escapeshellarg($acmeConfDir) . " --set-default-ca --server letsencrypt 2>&1", $caOutput, $caExitCode);
				if($caExitCode != 0) {
					$errormsg = _('Could not save ACME configuration. The following errors occurred<br>') . implode("<br>", array_map('htmlspecialchars', $caOutput));
					$this->message = array('type' => 'danger', 'message' => $errormsg);
					return ;
				}
				$register_account = exec(escapeshellarg($acmeBinary) . " --config-home " . escapeshellarg($acmeConfDir) . " --register-account 2>&1", $regOutput, $regExitCode);
				if($regExitCode != 0) {
					$errormsg = _('Could not save ACME configuration. The following errors occurred<br>') . implode("<br>", array_map('htmlspecialchars', $regOutput));
					$this->message = array('type' => 'danger', 'message' => $errormsg);
					return ;
				}
				$update_email = exec(escapeshellarg($acmeBinary) . " --config-home " . escapeshellarg($acmeConfDir) . " --update-account --accountemail '" . escapeshellarg($acmeEmail) . "' 2>&1", $emailOutput, $emailExitCode);
				if($emailExitCode != 0) {
					$errormsg = _('Could not save ACME configuration. The following errors occurred<br>') . implode("<br>", array_map('htmlspecialchars', $emailOutput));
					$this->message = array('type' => 'danger', 'message' => $errormsg);
					return ;
				}
				if($acmeUpdateMethod == 'cron') {
					$this->removeCronJob();
					$add_cron = exec('HOME=' . escapeshellarg($acmeConfDir) . ' ' . escapeshellarg($acmeBinary) . " --config-home " . escapeshellarg($acmeConfDir) . " --installcronjob 2>&1", $cronOutput, $cronExitCode);
					if($cronExitCode != 0) {
						$errormsg = _('Could not save ACME configuration. The following errors occurred<br>') . implode("<br>", array_map('htmlspecialchars', $cronOutput));
						$this->message = array('type' => 'danger', 'message' => $errormsg);
						return ;
					}
				}
				elseif($acmeUpdateMethod == 'freepbx') {
					$remove_cron = exec(escapeshellarg($acmeBinary) . " --config-home " . escapeshellarg($acmeConfDir) . " --uninstallcronjob 2>&1", $cronDelOutput, $cronDelExitCode);
					if($cronDelExitCode != 0) {
						$errormsg = _('Could not save ACME configuration. The following errors occurred<br>') . implode("<br>", array_map('htmlspecialchars', $cronDelOutput));
						$this->message = array('type' => 'danger', 'message' => $errormsg);
						return ;
					}
					$this->addAutoUpdateCron();
				}
			}
			$this->setConfig('acmeBinary', $acmeBinary);
			$this->setConfig('acmeConfdir', $acmeConfDir);
			$this->setconfig('acmeEmail', $acmeEmail);
			$this->setConfig('acmeUpdateMethod', $acmeUpdateMethod);
		}
	return true;
	}

	public function myShowPage($view=''){
		$view = !empty($this->goto) ? $this->goto : $view;
		$request = $_REQUEST;
		switch ($request['action'] ?? '') {
			case 'download':
				case 'csr':
					$csrs = $this->getAllManagedCSRs();
					$file = $this->PKCS->getKeysLocation()."/".$csrs[0]['basename'].".csr";
					if(!empty($csrs[0]['basename']) && file_exists($file)) {
						$quoted = sprintf('"%s"', addcslashes(basename($file), '"\\'));
						$size = filesize($file);
						header('Content-Description: File Transfer');
						header('Content-Type: application/octet-stream');
						header('Content-Disposition: attachment; filename=' . $quoted);
						header('Content-Transfer-Encoding: binary');
						header('Connection: Keep-Alive');
						header('Expires: 0');
						header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
						header('Pragma: public');
						header('Content-Length: ' . $size);
						readfile($file);
					}
					die();
				break;
			break;
			case 'add':
				switch($request['type']) {
					case 'le':
						// Have we been asked to update firewall rules?
						$hostname = $this->PKCS->getHostname();

						//Load acmesettings
						$settings = $this->loadAcmeSettings();
						$acmeMessage = array();
						if($settings['acmeBinary'] == '' || $settings['acmeConfDir'] == '') {
							$acmeMessage = array('type' => 'danger', 'message' => _('You have to set the <a href="/admin/config.php?display=certman&action=showAcmeSettings">ACME settings</a> before you can issue a certificate'));
						}

						echo load_view(__DIR__.'/views/le.php',array('message' => $this->message, 'hostname' => $hostname, 'settings' => $settings, 'acmeMessage' => $acmeMessage));
					break;
					case 'up':
						$csrs = $this->getAllManagedCSRs();
						echo load_view(__DIR__.'/views/up.php',array('cert' => [],'message' => $this->message, 'csrs' => $csrs));
					break;
					case 'ss':
						$hostname = $this->PKCS->getHostname();
						$pass = base64_encode(openssl_random_pseudo_bytes(32));
						$caExists = $this->checkCAexists();
						$cas = $this->getAllManagedCAs();
						echo load_view(__DIR__.'/views/ss.php',array('caExists' => $caExists, 'cas' => $cas, 'message' => $this->message,'pass' => $pass, 'hostname' => $hostname));
					break;
					case 'csr':
						$hostname = $this->PKCS->getHostname();
						$csrs = $this->getAllManagedCSRs();
						echo load_view(__DIR__.'/views/csr.php',array('message' => $this->message, 'csrs' => $csrs, 'hostname' => $hostname));
					break;
				}
			break;
			case 'view':
				// Have we been asked to update firewall rules?
				$cert = $this->getCertificateDetails($request['id']);
				$certinfo = array();
				if(file_exists($cert['files']['crt'])) {
					$certinfo = openssl_x509_parse(file_get_contents($cert['files']['crt']));
				}
				//FREEPBX-15408 WhoopsException\ErrorException Illegal string offset 'validTo_time_t'
				if (!array_key_exists("validTo_time_t",$certinfo)){
					$certinfo['validTo_time_t'] = '';
				}
				if(!empty($cert)) {
					switch($cert['type']) {
						case 'up':
							$csrs = $this->getAllManagedCSRs();
							echo load_view(__DIR__.'/views/up.php',array('cert' => $cert, 'message' => $this->message, 'csrs' => $csrs, 'certinfo' => $certinfo));
						break;
						case 'ss':
							$caExists = $this->checkCAexists();
							$cas = $this->getAllManagedCAs();
							if($cas){
								echo load_view(__DIR__.'/views/ss.php',array('cert' => $cert, 'caExists' => $caExists, 'cas' => $cas, 'message' => $this->message, 'certinfo' => $certinfo));
							}
						break;
						case 'le':
							echo load_view(__DIR__.'/views/le.php',array('cert' => $cert, 'message' => $this->message, 'certinfo' => $certinfo));
						break;
					}
				}
			break;
			case 'showAcmeSettings':
				// Display/edit settings for the ACME client
				 $settings = $this->loadAcmeSettings(true);
				echo load_view(__DIR__ . '/views/acmesettings.php', $settings);
			break;
			default:
				$certs = $this->getAllManagedCertificates();
				$csr = $this->checkCSRexists();
				$ca = $this->checkCAexists();
				$location = $this->PKCS->getKeysLocation();
				echo load_view(__DIR__.'/views/overview.php',array('certs' => $certs, 'location' => $location, 'message' => $this->message, 'csr' => $csr, 'ca' => $ca));
			break;
		}
	}

	/**
	 * loadAcmeSettings
	 * 
	 * This function loads the ACME settings and returns them as an associative array. 
	 * If withDefaults is set to true, default values are returned for missing or 
	 * empty configuration keys.
	 *
	 * @param  bool $withDefaults
	 * @return array
	 */
	private function loadAcmeSettings(bool $withDefaults = false) {
		$acmeBinary = $this->getConfig('acmeBinary');
		// Since acme.sh is not installed in the user’s home directory when installed via a package manager, 
		// we need to store the path to the acme.sh configuration directory separately
		$acmeConfDir = $this->getConfig('acmeConfDir');
		$acmeEmail = $this->getConfig('acmeEmail');
		$acmeUpdateMethod = $this->getConfig('acmeUpdateMethod');
		if (!$withDefaults) {
			return [
				'acmeBinary' => $acmeBinary,
				'acmeConfDir' => $acmeConfDir,
				'acmeEmail' => $acmeEmail,
				'acmeUpdateMethod' => $acmeUpdateMethod,
			];
		}
		return [
				'acmeBinary' => $acmeBinary ?: '/home/asterisk/.acme.sh/acme.sh',
				'acmeConfDir' => $acmeConfDir ?: '/home/asterisk/.acme.sh',
				'acmeEmail' => $acmeEmail ?: '',
				'acmeUpdateMethod' => $acmeUpdateMethod ?: '',
			];
	}

	public function getActionBar($request) {
		$buttons = array();
		$request['action'] = !empty($request['action']) ? $request['action'] : "";
		$buttons = array(
			'delete' => array(
				'name' => 'delete',
				'id' => 'Delete',
				'value' => _('Delete')
				),
				'reset' => array(
					'name' => 'reset',
					'id' => 'Reset',
					'value' => _('Reset')
				),
				'submit' => array(
					'name' => 'submit',
					'id' => 'Submit',
					'value' => _('Submit')
				)
			);
			switch($request['action']){
				case 'view':
					$buttons['submit']['value'] = _('Update Certificate');
					$buttons['delete']['value'] = _('Delete Certificate');
				break;
				case 'add':
				case 'new':
					unset($buttons['delete']);
					$buttons['submit']['value'] = isset($_REQUEST['type']) && $_REQUEST['type'] == 'csr' ? _('Generate CSR') : _('Generate Certificate');
				break;
				case "showAcmeSettings":
					$buttons['submit']['value'] = _('Save');
				break;
				default:
					$buttons = array();
				break;
			}
		return $buttons;
	}

	/**
	 * Check and/or update all certificates
	 *
	 * If a certificate can't be automatically updated add a notice in the interface
	 *
	 *  @param bool $force Force update regardless of expiration date
 	 *  @return array List of status messages generated during processing
	 */
	public function checkUpdateCertificates($force = false) {
		$certs = $this->getAllManagedCertificates();
		$messages = array();
		$nt = \notifications::create();
		$anyUpdated = false;
		foreach($certs as $cert) {
			$cert = $this->getAdditionalCertDetails($cert);
			if(empty($cert['files'])) {
				//there are no files so delete this one
				$this->removeCertificate($cert['cid']);
				$messages[] = array('type' => 'danger', 'message' => sprintf(_('There were no files left for certificate "%s" so it was removed'),$cert['basename']));
				continue;
			}
			$validTo = $cert['info']['crt']['validTo_time_t'];
			$renewafter = $validTo-(86400*$this->days_expiration_alert);
			$update = false;

			// Has this certificate expired?
			if(time() > $validTo) {
				if($cert['type'] == 'le') {
					try {

						// This will probably fail if they're using http_S_ with an expired
						// cert, but LE should never get to this point.
						$settings = array(
							"challengetype" => $cert['additional']['challengetype'] ?? '',
							"dnsprovider" => $cert['additional']['dnsprovider'] ?? '',
							"san" => $cert['additional']['san'] ?? '',
						);

						$this->updateLE($cert['info']['crt']['subject']['CN'], $settings, [], [], false, false, $force);

						// If that didn't throw, the certificate was succesfully updated
						$messages[] = array('type' => 'success', 'message' => sprintf(_('Successfully updated certificate named "%s"'),$cert['basename']));
						$this->FreePBX->astman->Reload();

						//Until https://issues.asterisk.org/jira/browse/ASTERISK-25966 is fixed
						$a = fpbx_which("asterisk");
						if(!empty($a)) {
							exec($a . " -rx 'dialplan reload'");
						}
						$update = true;
					} catch(Exception $e) {
						$einfo = json_decode(substr($e->getMessage(), strpos($e->getMessage(), '{')), true);
						$hints = array();
						if (!empty($einfo['detail'])) {
							$emessage = $einfo['detail'];
						} else {
							$emessage = $e->getMessage();
						}
						if (!empty($einfo['hints'])) {
							$hints = $einfo['hints'];
						}
						$messages[] = array('type' => 'danger', 'message' => sprintf(_('There was an error updating certificate "%s": %s'),($cert['basename'] ?? ''),$emessage), 'hints' => ($einfo['hints'] ?? ''));
						continue;
					}
				} else {
					$messages[] = array('type' => 'warning', 'message' => sprintf(_('Certificate named "%s" has expired. Please update this certificate in Certificate Manager'),($cert['basename'] ?? '')));
					continue;
				}
			} elseif (time() > $renewafter || $force) {
				// It hasn't expired, but it should be renewed.
				if($cert['type'] == 'le') {
					try {
						$settings = array(
							"challengetype" => $cert['additional']['challengetype'] ?? '',
							"dnsprovider" => $cert['additional']['dnsprovider'] ?? '',
							"san" => $cert['additional']['san'] ?? '',
						);

						$this->updateLE($cert['info']['crt']['subject']['CN'], $settings, [], [], false, false, $force);
						$messages[] = array('type' => 'success', 'message' => sprintf(_('Successfully updated certificate named "%s"'),$cert['basename']));
						$this->FreePBX->astman->Reload();
						//Until https://issues.asterisk.org/jira/browse/ASTERISK-25966 is fixed
						$a = fpbx_which("asterisk");
						if(!empty($a)) {
							exec($a . " -rx 'dialplan reload'");
						}
						$update = true;
					} catch(Exception $e) {
						$einfo = json_decode(substr($e->getMessage(), strpos($e->getMessage(), '{')), true);
						$hints = array();
						if (!empty($einfo['detail'])) {
							$emessage = $einfo['detail'];
						} else {
							$emessage = $e->getMessage();
						}
						if (!empty($einfo['hints'])) {
							$hints = $einfo['hints'];
						}
						$messages[] = array('type' => 'danger', 'message' => sprintf(_('There was an error updating certificate "%s": %s'),($cert['basename'] ?? ''),$emessage), 'hints' => ($einfo['hints'] ?? ''));
						continue;
					}
				} else {
					if(time() > $renewafter) {
						$messages[] = array('type' => 'warning', 'message' => sprintf(_('Certificate named "%s" is going to expire in less than a month. Please update this certificate in Certificate Manager'),$cert['basename']));
					}
					continue;
				}
			} else {
				$messages[] = array('type' => 'success', 'message' => sprintf(_('Certificate named "%s" is valid'),$cert['basename']));
				if($nt->exists("certman", "EXPIRINGCERTS")) {
					$nt->delete("certman", "EXPIRINGCERTS");
				}
			}
			//trigger hook only if we really updated though
			if($update) {
				$anyUpdated = true;
				$this->updateCertificate($cert, $cert['description'], $cert['additional']);
				exec(fpbx_which("fwconsole")." reload");
				// Reload HAProxy
				$this->reloadHAProxyIfEnabled();
			}
		}
		$notification = '';
		foreach($messages as $m) {
			if('warning' == $m['type'] || 'danger' == $m['type']){
				$notification .= $m['message'] . "</br>";
			}
		}
		if(!empty($notification)) {
			$nt->add_security("certman", "EXPIRINGCERTS", _("Some Certificates are expiring or have expired"), $notification, "config.php?display=certman", true, true);
		}else{
			$nt->delete("certman", "EXPIRINGCERTS");
		}
		if($anyUpdated) {
			$nt->add_update("certman", "UPDATEDCERTS", _("Certificate Update"), _("Some SSL/TLS Certificates have been automatically updated. You may need to ensure all services have the correctly update certificate by restarting PBX services"), "", true,true);
			if($nt->exists("certman", "EXPIRINGCERTS")) {
				$nt->delete("certman", "EXPIRINGCERTS");
			}
		}
		return $messages;
	}

	/**
	 * Determine location of the system CA Bundle
	 * @method getCABundle
	 * @return string      The location of the system CA bundle
	 */
	public function getCABundle() {
		return CaBundle::getSystemCaRootBundlePath();
	}

	/**
	 * Update or Add Let's Encrypt
	 * @param  string $host     The hostname (MUST BE A VALID FQDN)
	 * @param  array $settings  Array of settings for this certificate
	 * @param  array $dnsKeys	DNS API credential variable names (only used when challenge type is dns01)
	 * @param  array $dnsValues	DNS API credential values (only used when challenge type is dns01)
	 * @param  boolean $dnsCredentialsChanged 
	 * @param  boolean $staging Whether to use the staging server or not
	 * @param  boolean $force Force renew reguardless of expiration date
	 *
	 * @return boolean          True if success, false if not
	 */
	public function updateLE($host, $settings = false, $dnsKeys = [], $dnsValues = [], $dnsCredentialsChanged = false, $staging = false, $force = false) {
		/**
		 * Enable LE rules and set a delay for disabling LE rules.
		 * The time remaining is between 1 and 2 minutes before to close the door.
		 * It's good to close the door even if there is any error before the end of process.
		 * No need to execute a delay if this one is not performed yet.
		 * Using process to handle enable and disable of LE Rules
		 */
		if (!is_array($settings)) {
			throw new Exception("BUG: Settings is not an array. Old code?");
		}

		if($settings['challengetype'] === 'http01' && !$this->checkFirewallAndIpset()){
			throw new Exception("Please install ipset package And Restart the Firewall to continue");
		}
		$acmesettings = $this->loadAcmeSettings(false);
		if($acmesettings['acmeBinary'] === '' || $acmesettings['acmeConfDir'] === '') {
			throw new Exception("Please configure acme.sh (binary and config directory) in Certman before issuing Let's Encrypt certificates.");
		}
		// Get our variables from $settings
		$challengetype = !empty($settings['challengetype']) ? $settings['challengetype'] : '';
		$san = !empty($settings['san']) ? $settings['san'] : array();
		if($challengetype === 'dns01') {
			$dnsprovider =  !empty($settings['dnsprovider']) ? $settings['dnsprovider'] : '';
		}

		$acmeAction = '';
		//do we need to update the DNS API credentials?
		$updateDnsCredentials = false;
		$location = $this->PKCS->getKeysLocation();
		$host = basename($host);
		$exportName = $this->getFileBasename($host);
		$exportBase = $location . '/' . $exportName;
		array_unshift($san, $host);

		$needsgen = false;
		$certfile = $exportBase . ".crt";

		$user = $this->FreePBX->Config->get("AMPASTERISKWEBUSER");
		$group = $this->FreePBX->Config->get("AMPASTERISKWEBGROUP");
		$webroot = $this->FreePBX->Config->get("AMPWEBROOT");

		$hints = array();

		if (!file_exists($certfile)) {
			// We don't have a cert, so we need to request one.
			$needsgen = true;
			$acmeAction = '--issue';
			if($challengetype === 'dns01') {
				$updateDnsCredentials = true;
			}
		} else {
			// We DO have a certificate.
			$certdata = openssl_x509_parse(file_get_contents($certfile));
			// If it expires in less than a month, we want to renew it.
			$renewafter = $certdata['validTo_time_t']-(86400*$this->days_expiration_alert);
			if (time() > $renewafter) {
				// Less than a month left, we need to renew.
				$needsgen = true;
				$acmeAction = '--renew';
			}
		}
		if ($force && !$needsgen) {
    		$acmeAction = '--issue';
			if($challengetype === 'dns01' && $dnsCredentialsChanged) {
    			$updateDnsCredentials = true;
			}
		}

		try{
			if($challengetype =='http01') {
				$this->enableFirewallLeRules();

				$localip = gethostbyname($host);
				$localip = @inet_pton($localip) ? $localip : 'dns error';
				$publicip = $this->getPublicIP($host);
				$publicip = (!empty($publicip) && @inet_pton($publicip[0])) ? $publicip[0] : 'dns error';

				print(sprintf(_("Processing: %s, Local IP: %s, Public IP: %s\n"), $host, $localip, $publicip));

				//self-test first
				//	if this fails the equivalent code in Lesript.php will fail cryptically
				if($needsgen || $force) {
					$basePathCheck = "/.freepbx-known";
					if(!file_exists($webroot.$basePathCheck)) {
						$mkdirok = @mkdir($webroot.$basePathCheck,0777);
						if (!$mkdirok) {
							throw new Exception(_("Unable to create directory ").$webroot.$basePathCheck);
						}
					}
					$token = bin2hex(openssl_random_pseudo_bytes(16));
					$pathCheck = $basePathCheck."/".$token;
					file_put_contents($webroot.$pathCheck,$token);

					print(_("Self test: trying ") . "http://" . $host.$pathCheck . "\n");
					$pest = new \Pest("http://".$host);
					$pest->curl_opts[CURLOPT_FOLLOWLOCATION] = true;
					$pest->curl_opts[CURLOPT_CONNECTTIMEOUT] = 5;
					$pest->curl_opts[CURLOPT_TIMEOUT] = 5;
					try {
						$selftest = $pest->get($pathCheck);
					} catch(Exception $e) {
						$selftesterr = _("Self test error: ") . get_class($e) . " - " . trim(strip_tags($e->getMessage()));
						$hints[] = sprintf(_("Does DNS for %s resolve correctly?\nLocal DNS result: %s, External DNS result: %s"), $host, $localip, $publicip);
						print($selftesterr ."\n");
						@unlink($webroot.$pathCheck);
						throw new Exception(json_encode(['type' => 'selftest', 'detail' => $selftesterr, 'hints' => $hints]));
					}
					if(empty($selftest)) {
						$selftesterr = _("Self test error: no token data");
						print($selftesterr ."\n");
						@unlink($webroot.$pathCheck);
						throw new Exception($selftesterr);
					}
					print("Self test: received ". $selftest . "\n");

				//Now check freepbx.org
				//	on failure, save error as hint and continue
					try {
						$pest = new \PestJSON('http://mirror1.freepbx.org');
						$pest->curl_opts[CURLOPT_FOLLOWLOCATION] = true;
						$pest->curl_opts[CURLOPT_CONNECTTIMEOUT] = 10;
						$pest->curl_opts[CURLOPT_TIMEOUT] = 30;
						$thing = $pest->get('/lechecker.php', array('host' => $host, 'path' => $pathCheck, 'token' => $token, 'type' => $challengetype));
						if(empty($thing)) {
							$lecheckerr = _("No valid response from http://mirror1.freepbx.org");
						} elseif(!$thing['status']) {
							$lecheckerr = $thing['message'];
						}
					} catch(Exception $e) {
						$lecheckerr =  _("lechecker: ") . get_class($e) . " - " . trim(strip_tags($e->getMessage()));
					}
					if (isset($lecheckerr)) {
						print($lecheckerr . "\n");
						$hints[] = $lecheckerr;
					}
					@unlink($webroot.$pathCheck);
				}
			}

			//Now check let's encrypt
			if($needsgen || $force) {
				// Build shell-safe acme.sh command arguments and environment variables (used for dns-challenge)
				$acmeArgs = [];
				$envVars = [];
				$acmeArgs[] = $acmeAction;
				if($force) {
					$acmeArgs[] = "--force";
				}
				if($challengetype === 'http01') {
					$acmeArgs[] = "-w " . $webroot;
				}
				elseif($challengetype === 'dns01') {
					$acmeArgs[] = "--dns " . escapeshellarg($dnsprovider);
					if($updateDnsCredentials) {
						foreach ($dnsKeys as $idx => $key) {
							if (!isset($dnsValues[$idx])) {
								continue;
							}
							$value = $dnsValues[$idx];
							$envVars[] = $key . '=' . escapeshellarg($value);
						}
					}
				}
				foreach($san AS $d) {
					$acmeArgs[] = "-d " . escapeshellarg($d);
				}

				if($staging) {
					$acmeArgs[] = '--server https://acme-staging-v02.api.letsencrypt.org/directory';
				}
				// issue/renew certificate
				$acmecmd = implode(' ', $envVars) . ' ' . escapeshellcmd($acmesettings['acmeBinary'])  
						. ' --config-home ' . escapeshellarg($acmesettings['acmeConfDir']) 
						. ' ' . implode(' ', $acmeArgs) . ' 2>&1';
				exec($acmecmd, $output, $ret);
				if($ret != 0) {
					throw new Exception(json_encode(['type' => 'acme', 'detail' => _('acme.sh failed'), 'hints' => [implode("\n", $output)]]));
				}

				// Let acme.sh install the certificate files into the target directory
				$acmeCopyCmd = escapeshellarg($acmesettings['acmeBinary']) . ' --config-home ' 
				. escapeshellarg($acmesettings['acmeConfDir']) . ' --install-cert -d ' . escapeshellarg($host) 
				. ' --cert-file ' . escapeshellarg($exportBase . '.crt') . ' --key-file ' 
				. escapeshellarg($exportBase . '.key') . ' --ca-file ' . escapeshellarg($exportBase 
				. '-ca-bundle.crt') . ' --fullchain-file ' . escapeshellarg($exportBase . '-fullchain.crt') . ' 2>&1';
				exec($acmeCopyCmd, $outputCopy, $retCopy);
				if($retCopy != 0) {
					throw new Exception(json_encode(['type' => 'acme', 'detail' => _('acme.sh failed'), 'hints' => [implode("\n", $output)]]));
				}
				
				// Build combined PEM file (legacy format for backward compatibility)
				// NOTE: The .pem file contains private key + certificate + CA chain in one file.
				// This format may still be used by other FreePBX/Asterisk components or third-party modules.
				// Do NOT remove or change this structure without verifying downstream consumers.
				$key = file_get_contents($exportBase . '.key');
				if ($key === false) {
					throw new Exception("Unable to read private key");
				}
				$cert = file_get_contents($exportBase . '.crt');
				if ($cert === false) {
					throw new Exception("Unable to read certificate");
				}
				$bundle = file_get_contents($exportBase . '-ca-bundle.crt');
				if ($bundle === false) {
					throw new Exception("Unable to read CA bundle");
				}
				$result = file_put_contents($exportBase . '.pem', $key . "\n" . $cert . "\n" . $bundle);
				if ($result === false) {
    				throw new Exception("Unable to write combined PEM file");
				}
			}
			if($challengetype === 'http01') {
				$this->disableFirewallLeRules();
			}
			
			$exts = array(".key", ".crt", ".pem", "-ca-bundle.crt");
			foreach($exts as $ext){
				chmod($exportBase . $ext, 0600);
				$chown[] = $exportBase . $ext;
			}
			if(!empty($chown) && posix_geteuid() === 0) {
				foreach($chown as $file) {
					chown($file, $user);
					chgrp($file, $group);
				}
			}
			return true;
		} catch(Exception $e) {
			if($challengetype === 'http01') {
				$this->disableFirewallLeRules();
				// clean up challenge tokens on failed requests
				// we know the lechecker file name
				@unlink($webroot.$pathCheck);
			}
			$einfo = json_decode($e->getMessage(), true);
			if (!is_array($einfo)) {
    			$einfo = [];
			}
			if (!$einfo) $einfo = array();
			$einfo['detail'] = !empty($einfo['detail']) ? $einfo['detail'] : $e->getMessage();
			$einfo['type'] = !empty($einfo['type']) ? $einfo['type'] : "unknown";
			$einfo['hints'] = !empty($einfo['hints']) ? array_merge($hints, $einfo['hints']) : $hints;
			throw new Exception(json_print_pretty(json_encode($einfo), "  "));
		}
	}

	/* enable firewall rules */
	private function enableFirewallLeRules() {
		$api = $this->getFirewallAPI();
		$module_info = module_getinfo('firewall', MODULE_STATUS_ENABLED);
		if(isset($module_info["firewall"]) && $api->isAvailable()){
			$api->enableLeRules();
			usleep(500000);
		}
	}

	/* disable firewall lerules */
	private function disableFirewallLeRules() {
		$api = $this->getFirewallAPI();
		$module_info = module_getinfo('firewall', MODULE_STATUS_ENABLED);
		if(isset($module_info["firewall"]) && $api->isAvailable()){
			$api->disableLeRules();
		}
	}

	/* check firewall is enabled or not*
	if firewall enabled then check the version 13.0.60.13
	check ipset is installed or not
	return true/flase
	*/
	private function checkFirewallAndIpset() {
		$mf = \module_functions::create();
		$firewall = $mf->getinfo('firewall');
		//firewall not present in system
		if(!isset($firewall['firewall'])){
			return true;
		}
		//fire wall module not enabled
		if (isset($firewall['firewall']['status']) && $firewall['firewall']['status'] != 2) {
			return true;
		}
		$api = $this->getFirewallAPI();
		if(!$api->isAvailable()){
			return true;
		}
		// check firewall version having ipset
		if (version_compare_freepbx($firewall['firewall']['version'],'15.0.6.29','<')) {
			throw new Exception(_("There was an error updating the certificate: Firewall v 15.0.6.29 and above required please install"));
		}
		$ipset = fpbx_which("ipset") ;
		if($ipset ==''){
			return false;
		}
		return true;
	}
	/**
	 * FreePBX chown hooks
	 */
	public function chownFreepbx() {
		$certs = $this->getAllManagedCertificates();
		$location = $this->PKCS->getKeysLocation();
		$files[] = array('type' => 'rdir',
				'path' => $location . "/_account",
				'perms' => 0600);
		$files[] = array('type' => 'file',
				'path' => $location . "/_account",
				'perms' => 0755);
		foreach($certs as $cert) {
			if ($cert['type'] == 'le') {
				$files[] = array('type' => 'rdir',
					'path' => $location . "/" . $cert['basename'],
					'perms' => 0600);
				$files[] = array('type' => 'file',
					'path' => $location . "/" . $cert['basename'],
					'perms' => 0755);
			}
			$details = $this->getCertificateDetails($cert['cid']);
			if(!empty($details['files'])) {
				foreach($details['files'] as $file) {
					$files[] = array('type' => 'file',
						'path' => $file,
						'perms' => 0600);
				}
			}
			if(!empty($details['integration']['files'])) {
				foreach($details['integration']['files'] as $file) {
					$files[] = array('type' => 'file',
						'path' => $file,
						'perms' => 0600);
				}
			}
		}
		return $files;
	}

	/**
	 * Validate and import a certificate
	 *
	 * IF any private key has a passphrase this WILL strip the passphrase!!
	 *
	 * @param  string $name              The certificate basename
	 * @param  string $privateKey        RAW Private Key
	 * @param  string $signedCertificate RAW Signed Certificate
	 * @param  string $certificateChain  RAW Certificate Chain
	 * @param  string $passphrase        Passphrase to decrypt private key
	 */
	public function importCertificate($name, $privateKey, $signedCertificate, $certificateChain='', $passphrase='') {
		$location = $this->PKCS->getKeysLocation();
		$name = basename($name);

		if(empty($privateKey)) {
			throw new Exception(_('No Private key to reference. Try generating a CSR first.'));
		}

		if(empty($signedCertificate)) {
			throw new Exception(_('No Certificate provided'));
		}

		//https://stackoverflow.com/questions/11852476/php-removing-windows-m-character
		//Remove Windows control characters from certificate files as Asterisk
		//refuses to load the certifcate if it has them - Joao
		$privateKey = str_ireplace("\x0D", "", $privateKey);
		$signedCertificate = str_ireplace("\x0D", "", $signedCertificate);
		if(!empty($certificateChain)) {
			$certificateChain = str_ireplace("\x0D", "", $certificateChain);
		}

		if(file_exists($location."/".$name.".key") && !is_writable($location."/".$name.".key")) {
			throw new Exception(sprintf(_('Unable to write to %s'),$location."/".$name.".key"));
		}

		if(file_exists($location."/".$name.".crt") && !is_writable($location."/".$name.".crt")) {
			throw new Exception(sprintf(_('Unable to write to %s'),$location."/".$name.".crt"));
		}

		if(file_exists($location."/".$name.".pem") && !is_writable($location."/".$name.".pem")) {
			throw new Exception(sprintf(_('Unable to write to %s'),$location."/".$name.".pem"));
		}

		if(empty($passphrase)) {
			$keyTest = openssl_pkey_get_private($privateKey);
		} else {
			$keyTest = openssl_pkey_get_private($privateKey,$passphrase);
		}
		if($keyTest === false) {
			throw new Exception(_('Unable to read key. Is it password protected?'));
		}
		$certTest = openssl_x509_read($signedCertificate);
		if(!openssl_x509_check_private_key($certTest, $keyTest)) {
			throw new Exception(_('Key does not match certificate'));
		}
		file_put_contents($location."/".$name.".key", $privateKey);

		//strip the passphrase
		if(!empty($_POST['passphrase'])) {
			$this->PKCS->runOpenSSL("rsa -in ".$location."/".$name.".key -out ".$location."/".$name."np.key -passin stdin",$passphrase);
			unlink($location."/".$name.".key"); //jic
			$privateKey = file_get_contents($location."/".$name."np.key");
			unlink($location."/".$name."np.key"); //jic
			file_put_contents($location."/".$name.".key", $privateKey);

			//Now test again without the password to make sure this all works correctly
			$keyTest = openssl_pkey_get_private($privateKey);
			if(!openssl_x509_check_private_key($certTest, $keyTest)) {
				throw new Exception(_('Key does not match certificate after password removal'));
			}
		}

		file_put_contents($location."/".$name.".crt", $signedCertificate);

		if(!empty($certificateChain)) {
			file_put_contents($location."/".$name."-ca-bundle.crt", $certificateChain);
			$bundle = file_get_contents($location."/".$name."-ca-bundle.crt");
			file_put_contents($location . "/" . $name . ".pem", $privateKey ."\n". $signedCertificate."\n".$bundle);
			chmod($location."/".$name."-ca-bundle.crt",0600);
			file_put_contents($location . "/" . $name . "-fullchain.crt", $signedCertificate . "\n" . $bundle);
			chmod($location."/".$name."-fullchain.crt",0600);
		} else {
			file_put_contents($location . "/" . $name . ".pem", $privateKey ."\n". $signedCertificate);
		}


		chmod($location."/".$name.".crt",0600);
		chmod($location."/".$name.".key",0600);
		chmod($location."/".$name.".pem",0600);
		return true;
	}

	public function myDialplanHooks() {
		return true;
	}

	/**
	 * Check if DTLS Autogenerated Certificate option is supported
	 * @return boolean
	 */
	public function pjsipDTLSAutoGenerateCertSupported() {
		$asteriskVersion = $this->FreePBX->Config->get('ASTVERSION');
		if (version_compare($asteriskVersion, '15.2', 'le')) {
			return false;
		}

		return true;
	}

	public function doDialplanHook(&$ext, $engine, $priority) {
		global $core_conf;

		foreach($this->getAllDTLSOptions() as $device) {
			$o = $this->FreePBX->Core->getDevice($device['id']);
			if(empty($o)) {
				continue;
			}

			// If auto_generate_cert is enabled but the asterisk version is not
			// supported, let's assume this is a downgrade situation and use the
			// default certificate
			$cert = array();
			if ((integer)$device['auto_generate_cert'] === 1) {
				if (!$this->pjsipDTLSAutoGenerateCertSupported()) {
					$cert = $this->getDefaultCertDetails();
				}
			} else {
				$cert = $this->getCertificateDetails($device['cid']);

				// if no certificate file found, do not enable DTLS
				if(empty($cert['files']['crt']) || empty($cert['files']['key'])) {
					continue;
				}
			}

			if($o['tech'] === 'sip') {
				$core_conf->addSipAdditional($device['id'], 'dtlsenable', 'yes');
				$core_conf->addSipAdditional($device['id'], 'dtlsverify', $device['verify']);
				$core_conf->addSipAdditional($device['id'], 'dtlscertfile', $cert['files']['crt']);
				$core_conf->addSipAdditional($device['id'], 'dtlsprivatekey', $cert['files']['key']);
				$core_conf->addSipAdditional($device['id'], 'dtlssetup', $device['setup']);
				$core_conf->addSipAdditional($device['id'], 'dtlsrekey', $device['rekey']);
			}

			if($o['tech'] === 'pjsip') {
				if (isset($o['media_encryption']) && $o['media_encryption'] == 'dtls') {
					$this->FreePBX->PJSip->addEndpoint($device['id'], 'dtls_verify', $device['verify']);
					$this->FreePBX->PJSip->addEndpoint($device['id'], 'dtls_setup', $device['setup']);
					$this->FreePBX->PJSip->addEndpoint($device['id'], 'dtls_rekey', $device['rekey']);
				}
				if ((integer)$device['auto_generate_cert'] === 1 && $this->pjsipDTLSAutoGenerateCertSupported()) {
					$this->FreePBX->PJSip->addEndpoint($device['id'], 'dtls_auto_generate_cert', 'yes');
					continue;
				}

				$this->FreePBX->PJSip->addEndpoint($device['id'], 'dtls_cert_file', $cert['files']['crt']);
				$this->FreePBX->PJSip->addEndpoint($device['id'], 'dtls_private_key', $cert['files']['key']);
			}
		}
	}

	/**
	 * Get all DTLS Settings for each extension
	 */
	public function getAllDTLSOptions() {
		$sql = "SELECT * FROM certman_mapping";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		return $sth->fetchAll(PDO::FETCH_ASSOC);
	}

	/**
	 * Get DTLS Settings for a particular extension
	 * @param {int} $device The device/extension number
	 */
	public function getDTLSOptions($device) {
		if(!isset($device)) {
			return false;
		}
		$sql = "SELECT * FROM certman_mapping WHERE id = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($device));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		if(!empty($data)) {
			$data['enable'] = 'yes';
		} else {
			return array(
				"enable" => "no",
				"verify" => "fingerprint",
				"cid" => "",
				"setup" => "actpass",
				"rekey" => "0",
				"auto_generate_cert" => "0"
			);
		}
		return $data;
	}

	/**
	 * Check to make sure said device has a valid certificate
	 * @param {int} $device The Extension/Device Number
	 */
	public function validDTLSDevice($device) {
		$sql = "SELECT * FROM certman_mapping WHERE id = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($device));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		if(!empty($data)) {
			if(!empty($data['cid'])) {
				$cert = $this->getCertificateDetails($data['cid']);
				if(!empty($cert) && $this->checkCAexists()) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Add DTLS Options for a device/extension
	 * @param {int} $device  The Device/Extension Number
	 * @param {array} $data	 An array of defined options
	 */
	public function addDTLSOptions($device, $data) {
		$autoGenerateCert = !empty($data['auto_generate_cert'])
			? $data['auto_generate_cert'] : 0;

		if ($autoGenerateCert && !$this->pjsipDTLSAutoGenerateCertSupported()) {
			dbug('DTLS autogenerate certificate option not available');
			return;
		}

		$certificate = empty($data['certificate']) ? null : $data['certificate'];
		if (!$autoGenerateCert && empty($certificate)) {
			dbug('DTLS certificate file not specified');
			return;
		}

		$sql = "REPLACE INTO certman_mapping (
			id,
			cid,
			verify,
			setup,
			rekey,
			auto_generate_cert
		) VALUES (?, ?, ?, ?, ?, ?)";
		$sth = $this->db->prepare($sql);
		$sth->execute(array(
			$device,
			$certificate,
			$data['verify'],
			$data['setup'],
			$data['rekey'],
			$autoGenerateCert
		));
	}

	/**
	 * Remove the DTLS Options for this device
	 * @param {int} $device The Device/Extension Number
	 */
	public function removeDTLSOptions($device) {
		$sql = "DELETE FROM certman_mapping WHERE id = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($device));
	}

	/**
	 * Check to see if *any* certificate authority exists
	 */
	public function checkCAexists() {
		$o = $this->getAllAuthorityFiles();
		$z = $this->getAllManagedCAs();
		if((!empty($o) && empty($z)) || (empty($o) && !empty($z))) {
			//files are missing from hard drive/database, so something is corrupt.
			//run delete to resolve
			$this->removeCA();
			return false;
		}
		return (empty($o) && empty($z)) ? false : true;
	}

	/**
	* Return a list of all Certificates from the key folder
	* @return array
	*/
	public function getAllAuthorityFiles() {
		$keyloc = $this->PKCS->getKeysLocation();
		$cas = array();
		$files = $this->PKCS->getFileList($keyloc);
		if(in_array('ca.key',$files)) {
			$cas[] = 'ca.key';
		}
		if(in_array('ca.crt',$files)) {
			$cas[] = 'ca.crt';
		}
		return $cas;
	}

	/**
	 * Check to see if *any* certificate authority exists
	 */
	public function checkCSRexists() {
		$z = $this->getAllManagedCSRs();
		return !empty($z);
	}

	/**
	 * Get all Certificate Manager Managed Certificate Authorities
	 */
	public function getAllManagedCAs() {
		$sql = "SELECT * FROM certman_cas";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		return $sth->fetchAll(PDO::FETCH_ASSOC);
	}

	/**
	 * Generate a New Certificate Authority
	 * @param {string} $basename	 The basename of the file to generate
	 * @param {string} $commonname The common name, usually FQDN or IP
	 * @param {string} $orgname		The organization name
	 */
	public function generateCA($basename, $commonname, $orgname) {
		if(empty($basename)) {
			throw new Exception("Basename can not be empty!");
		}
		if(empty($commonname)) {
			throw new Exception("Commonname can not be empty!");
		}
		if(empty($orgname)) {
			throw new Exception("Organization can not be empty!");
		}
		$this->generateConfig($basename,$commonname,$orgname);
		$this->PKCS->createCA($basename);
		return $this->saveCA($basename, $commonname, $orgname);
	}

	/**
	 * Generate OpenSSL Template Configs
	 * @param {string} $basename	 The CA Basename
	 * @param {string} $commonname The common name, usually FQDN or IP
	 * @param {string} $orgname		The organization name
	 */
	public function generateConfig($basename, $commonname, $orgname) {
		$this->PKCS->createConfig($basename,$commonname,$orgname);
	}

	/**
	 * Save the Certificate Authority Information into the Database
	 * @param {string} $basename	 The CA Basename
	 * @param {string} $commonname The common name, usually FQDN or IP
	 * @param {string} $orgname		The organization name
	 * @param {string} $passphrase The passphrase (to be encrypted)
	 */
	public function saveCA($basename, $commonname, $orgname) {
		$sql = "INSERT INTO certman_cas (`basename`, `cn`, `on`) VALUES (?, ?, ?)";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($basename, $commonname,$orgname));
		return $this->db->lastInsertId();
	}

	/**
	 * Save the Certificate Signing Request Information into the Database
	 * @param {string} $basename	 The CSR Basename
	 */
	public function saveCSR($basename) {
		if (is_array($basename)) {
			$basename = implode(',', $basename);
		}
		$sql = "INSERT INTO certman_csrs (`basename`) VALUES (?)";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($basename));
		return $this->db->lastInsertId();
	}

	/**
	 * Get Certificate Authority Details
	 * @param {int} $caid The Certificate Authority ID
	 */
	public function getCADetails($caid) {
		$sql = "SELECT * from certman_cas WHERE uid = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($caid));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		if(!empty($data)) {
			$location = $this->PKCS->getKeysLocation();
			$files = array(".key" => "key",".crt" => "crt",".cfg" => "cfg");
			foreach($files as $f => $type) {
				$file = $location.'/'.$data['basename'].$f;
				if(file_exists($file)) {
					$data['files'][$type] = $file;
				}
			}
		}
		return $data;
	}

	/**
	 * Get details about a certificate signing request
	 * @param  int $csrid The CSR id
	 * @return array        Array of data
	 */
	public function getCSRDetails($csrid) {
		$sql = "SELECT * from certman_csrs WHERE cid = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($csrid));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		if(!empty($data)) {
			$location = $this->PKCS->getKeysLocation();
			$files = array(".csr" => "csr",".csr-config" => "csr-config",".key" => "key");
			foreach($files as $f => $type) {
				$file = $location.'/'.$data['basename'].$f;
				if(file_exists($file)) {
					$data['files'][$type] = $file;
				}
			}
		}
		return $data;
	}

	/**
	 * Generate A Certificate Based on a Certificate Authority
	 * @param {int} $caid						The Managed Certificate Authority ID
	 * @param {string} $base						The base name to generate
	 * @param {string} $description		 Description of this certificate
	 */
	public function generateCertificate($caid, $base, $description) {
		if($this->checkCertificateName($base)) {
			throw new Exception(sprintf(_("%s already exists!"),$base));
		}
		$ca = $this->getCADetails($caid);
		$passphrase = $ca['passphrase'];
		$this->PKCS->createCert($base,$ca['basename'],$passphrase);
		return $this->saveCertificate($caid,$base,$description);
	}

	/**
	 * Save Certificate Information into the Database
	 * @param {int}    $caid				The Certificate Authority ID (For Self Signed)
	 * @param {string} $base				The base name of the certificate
	 * @param {string} $description The description of the certificate
	 * @param {string} $type				The type of the certificate: ss:: self signed, up:: upload, le:: let's encrypt
	 * @param {string} $additional  Additional data in an array format
	 */
	public function saveCertificate($caid=null, $base='', $description='', $type='ss', $additional=array()) {
		if($this->checkCertificateName($base)) {
			throw new Exception(sprintf(_("%s already exists!"),$base));
		}
		if (!is_array($additional)) {
			$additional = array();
		}

		$sql = "INSERT INTO certman_certs (`caid`, `basename`, `description`, `type`, `additional`) VALUES (?, ?, ?, ?, ?)";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($caid,$base,$description,$type,json_encode($additional)));
		$lastInsertId=$this->db->lastInsertId();
		$this->updateDefault();
		return $lastInsertId;
	}

	public function updateDefault() {
		$sql = "SELECT cid, `default` FROM certman_certs";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$results = $sth->fetchAll(PDO::FETCH_ASSOC);
		if (count($results) == 1 && $results[0]['default'] == 0) {
			$updateStmt = $this->db->prepare("UPDATE certman_certs SET `default` = 1 WHERE cid = ?");
			$updateStmt->execute([$results[0]['cid']]);
		}
	}

	/**
	 * Get all Managed Certificates (Excluding any Authorities)
	 */
	public function getAllManagedCertificates() {
		$sql = "SELECT * FROM certman_certs";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		return $sth->fetchAll(PDO::FETCH_ASSOC);
	}

	/**
	 * Get all Managed Certificate Signing Requests
	 */
	public function getAllManagedCSRs() {
		$sql = "SELECT * FROM certman_csrs";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		return $sth->fetchAll(PDO::FETCH_ASSOC);
	}

	public function getCertificateDetailsByBasename($basename) {
		$sql = "SELECT * from certman_certs WHERE basename = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($basename));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		if(!empty($data)) {
			$default = !empty($data['default']) ? true : false;
			$data = $this->getAdditionalCertDetails($data, $default);
		}
		return $data;
	}

	/**
	 * Get details about a specific Authority
	 * @param int $cid The Certificate ID
	 */
	public function getCertificateDetails($cid) {
		$sql = "SELECT * from certman_certs WHERE cid = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($cid));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		if(!empty($data)) {
			$default = !empty($data['default']) ? true : false;
			$data = $this->getAdditionalCertDetails($data, $default);
		}
		return $data;
	}

	/**
	 * Check Certificate Name to see if it exists
	 * @param {string} $name Certificate Base Name
	 * @return boolean True if it exists, false if it doesnt
	 */
	public function checkCertificateName($name) {
		$sql = "SELECT * FROM certman_certs WHERE basename = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($name));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		return !empty($data);
	}

	/**
	 * Check Certificate Name to see if it exists
	 * @param {string} $name Certificate Base Name
	 * @return boolean True if it exists, false if it doesnt
	 */
	public function checkCSRName($name) {
		$sql = "SELECT * FROM certman_csrs WHERE basename = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($name));
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		return !empty($data);
	}

	/**
	 * Remove a Certificate
	 * @param {int} $cid The Certificate ID to remove
	 */
	public function removeCertificate($cid) {
		$cert = $this->getCertificateDetails($cid);
		$location = $this->PKCS->getKeysLocation();
		if(empty($cert)) {
			return false;
		}
		foreach($cert['files'] as $file) {
			if(file_exists($file)) {
				if(!unlink($file)) {
					throw new Exception(sprintf(_('Unable to remove %s'),$file));
				}
			}
		}

		$sql = "DELETE FROM certman_certs WHERE cid = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($cid));
		return true;
	}

	/**
	 * Import local certificates that are in the keys folder but orphaned
	 * @return array Array of processed keys
	 */
	public function importLocalCertificates() {
		$location = $this->PKCS->getKeysLocation();
		$cas = $this->getAllAuthorityFiles();
		$keys = array();
		$processed = array();
		foreach(glob($location."/*.key") as $file) {
			$name = basename($file,".key");
			//API key from api module should ignore
			if($name == 'api_oauth' || $name == 'api_oauth_public') {
				continue;
			}
			if(in_array(basename($file),$cas)) {
				continue;
			}
			$raw = file_get_contents($file);
			if(empty($raw)) {
				$processed[] = array(
					"status" => false,
					"error" => _("Key is empty"),
					"file" => $file
				);
				continue;
			}
			$key = openssl_pkey_get_private($raw);
			if($key === false) {
				//key is password protected
				$processed[] = array(
					"status" => false,
					"error" => _("Key is password protected or malformed"),
					"file" => $file
				);
				continue;
			}
			$info = openssl_pkey_get_details($key);
			$keys[] = array(
				"file" => $file,
				"res" => $key,
				"raw" => file_get_contents($file)
			);
		}

		foreach(glob($location."/*.crt") as $file) {
			if(in_array(basename($file),$cas)) {
				continue;
			}
			$raw = file_get_contents($file);
			if(empty($raw)) {
				$processed[] = array(
					"status" => false,
					"error" => _("Certificate is empty"),
					"file" => $file
				);
				continue;
			}
			$info = openssl_x509_read($raw);
			foreach($keys as $key) {
				if (openssl_x509_check_private_key($info, $key['res'])) {
					$name = basename($file,".crt");
					try {
						$status = $this->importCertificate($name,$key['raw'],file_get_contents($file));
					} catch(\Exception $e) {
						$processed[] = array(
							"status" => false,
							"error" => $e->getMessage(),
							"file" => $file
						);
						continue;
					}
					$success = false;
					if($this->checkCertificateName($name)) {
						$oldDetails = $this->getCertificateDetailsByBasename($name);
						if (!empty($oldDetails) && $oldDetails['type'] == 'up') {
							$this->updateCertificate($oldDetails,_("Imported from file system"));
							$success = true;
						}
					} else {
						$this->saveCertificate(null,$name,_("Imported from file system"),'up');
						$success = true;
					}
					if ($success) {
						$processed[] = array(
							"status" => true,
							"file" => $file
						);
					}
				}
			}
		}
		return $processed;
	}

	/**
	 * Remove a Certificate Authority and all of it's child certificates
	 */
	public function removeCA() {
		$location = $this->PKCS->getKeysLocation();
		if(file_exists($location . "/ca.key")) {
			if(!unlink($location . "/ca.key")) {
				throw new Exception(_('Unable to remove ca.key'));
			}
		}
		if(file_exists($location . "/ca.crt")) {
			if(!unlink($location . "/ca.crt")) {
				throw new Exception(_('Unable to remove ca.crt'));
			}
		}
		if(file_exists($location . "/ca.cfg")) {
			if(!unlink($location . "/ca.cfg")) {
				throw new Exception(_('Unable to remove ca.cfg'));
			}
		}
		if(file_exists($location . "/tmp.cfg")) {
			if(!unlink($location . "/tmp.cfg")) {
				throw new Exception(_('Unable to remove tmp.cfg'));
			}
		}
		$sql = "TRUNCATE certman_cas";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		foreach($this->getAllManagedCertificates() as $cert) {
			if($cert['type'] == 'ss') {
				$this->removeCertificate($cert['cid']);
			}
		}
		return true;
	}

	/**
	 * Remove a Certificate Signing Request
	 */
	public function removeCSR($keepKey = false) {
		try {
			$csrs = $this->getAllManagedCSRs();
			$loc = $this->PKCS->getKeysLocation();
		} catch(Exception $e) {
			return false;
		}
		if(isset($csrs[0])){
			$files[] = $loc ."/".$csrs[0]['basename'].".csr";
			$files[] = $loc ."/".$csrs[0]['basename'].".csr-config";
			if(!$keepKey) {
				$files[] = $loc ."/".$csrs[0]['basename'].".key";
			}
			foreach($files as $file) {
				if(file_exists($file)) {
					unlink($file);
				}
			}
			$sql = "TRUNCATE certman_csrs";
			$sth = $this->db->prepare($sql);
			$sth->execute();
			return true;
		}else{
			return false;
		}	
	}

	/**
	 * Update Database about Cert
	 * @param  array $details         Old Cert info
	 * @param  string $description the cert description
	 * @return [type]              [description]
	 */
	public function updateCertificate($oldDetails, $description, $additional=array()) {
		if(!is_array($additional)) {
			$additional = array();
		}
		$sql = "UPDATE certman_certs SET description = ?, additional = ? WHERE cid = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array($description,json_encode($additional),$oldDetails['cid']));

		$newDetails = $this->getCertificateDetails($oldDetails['cid']);
		if(empty($newDetails)) {
			throw new Exception("Could not find updated certificates");
		}
		if(is_array($newDetails['files']) && posix_geteuid() === 0) {
			$user = $this->FreePBX->Config->get("AMPASTERISKWEBUSER");
			$group = $this->FreePBX->Config->get("AMPASTERISKWEBGROUP");
			foreach($newDetails['files'] as $file) {
				chown($file,$user);
				chgrp($file,$group);
			}
		}
		$this->FreePBX->Hooks->processHooks($newDetails,$oldDetails);
		//if this is a default certificate then run the default hooks
		if($newDetails['default']) {
			$this->makeCertDefault($oldDetails['cid']);
		}
		return ;
	}

	public function getRightNav($request) {
		if(isset($request['action']) && !empty($request['action'])){
			return load_view(__DIR__."/views/rnav.php",array('caExists' => $this->checkCAexists()));
		}
	}

	/**
	 * Make a certificate the default
	 * @param  int $cid The certificate ID
	 * @return bool      True if success
	 */
	public function makeCertDefault($cid) {
		$cert = $this->getCertificateDetails($cid);
		if(empty($cert)) {
			return false;
		}
		$sql = "UPDATE certman_certs SET `default` = 0";
		$sth = $this->db->prepare($sql);
		$sth->execute();

		$sql = "UPDATE certman_certs SET `default` = ? WHERE cid = ?";
		$sth = $this->db->prepare($sql);
		$sth->execute(array(1,$cid));

		$user = $this->FreePBX->Config->get("AMPASTERISKWEBUSER");
		$group = $this->FreePBX->Config->get("AMPASTERISKWEBGROUP");

		$location = $this->PKCS->getKeysLocation();
		if(!file_exists($location.'/integration')) {
			mkdir($location.'/integration',0777,true);
			if(posix_geteuid() === 0) {
				chown($location."/integration",$user);
				chgrp($location."/integration",$group);
			}
		}

		if(empty($cert['files']['crt']) || empty($cert['files']['key'])) {
			throw new Exception("Unable to make certficate default. Certificates are missing");
		}

		$sslfiles = array("pem" => "certificate.pem", "ca-crt" => "ca-bundle.crt", "crt" => "webserver.crt", "key" => "webserver.key");
		foreach ($sslfiles as $key => $f) {
			if (file_exists($location."/integration/$f")) {
				unlink($location."/integration/$f");
			}
			if(isset($cert['files'][$key])) {
				copy($cert['files'][$key],$location."/integration/$f");
				$cert['integration']['files'][$key] = $location."/integration/$f";
				chmod($location."/integration/$f",0600);
				if(posix_geteuid() === 0) {
					chown($location."/integration/$f",$user);
					chgrp($location."/integration/$f",$group);
				}
			}
		}

		if(isset($cert['files']['pem'])) {
			$this->FreePBX->Config->update("HTTPTLSCERTFILE",$location."/integration/certificate.pem");
		} else {
			$this->FreePBX->Config->update("HTTPTLSCERTFILE",$location."/integration/webserver.crt");
		}
		$this->FreePBX->Config->update("HTTPTLSPRIVATEKEY",$location."/integration/webserver.key");
		$this->FreePBX->Config->update("HTTPTLSENABLE",true);
		$this->FreePBX->Hooks->processHooks($cert);
		return true;
	}

	/**
	 * Get default certificate details
	 * @return array Array of certificate
	 */
	public function getDefaultCertDetails() {
		$sql = "SELECT * from certman_certs WHERE `default` = 1";
		$sth = $this->db->prepare($sql);
		$sth->execute();
		$data = $sth->fetch(PDO::FETCH_ASSOC);
		if(!empty($data)) {
			$data = $this->getAdditionalCertDetails($data, true);
		} else {
			$data = array(); //jic
		}
		return $data;
	}

	/**
	* Convert a certificate basename into a filesystem-safe export name.
 	*
 	* Wildcard-only certificates may use a basename starting with '*',
 	* which may lead to unexpected behaviour when used directly in
 	* exported certificate filenames. In this case, the wildcard prefix
	* is replaced with 'wildcard_'.
 	*
 	* Examples:
 	* - example.org     -> example.org
 	* - *.example.org   -> wildcard_example.org
 	*
 	* @param string $basename Certificate basename.
 	* @return string Filesystem-safe export name.
	*/
	private function getFileBasename(string $basename) {
		if(str_starts_with($basename, '*.')) {
			return 'wildcard_' . substr($basename, 2);
		}
		return $basename;
	}

	/**
	 * Get Additional Details about a certificate
	 * @param  array $details The previous details
	 * @param  boolean $default If this is a default certificate or not
	 * @return array          $details with more!
	 */
	private function getAdditionalCertDetails($details, $default=false) {
		$location = $this->PKCS->getKeysLocation();
		$files = array(".key" => "key",".crt" => "crt",".csr" => "csr",".pem" => "pem","-ca-bundle.crt" => "ca-bundle", "-fullchain.crt" => "fullchain");
		$details['files'] = !empty($details['files']) ? $details['files'] : array();
		$fileBasename = $this->getFileBasename($details['basename']);
		$details['hashes'] = !empty($details['hashes']) ? $details['hashes'] : array();
		$details['info'] = !empty($details['info']) ? $details['info'] : array();
		foreach($files as $f => $type) {
			$file = $location.'/'.$fileBasename.$f;
			if(file_exists($file)) {
				if(!is_readable($file)) {
					throw new Exception(sprintf(_("Certificate %s is not readable! Can not continue!"),$file));
				}
				$details['files'][$type] = $file;
				if($type == 'crt') {
					$details['info']['crt'] = @openssl_x509_parse(file_get_contents($file));
				}
				$details['hashes'][$type] = sha1_file($file);
			}
		}
		if($default) {
			$details['integration'] = !empty($details['integration']) ? $details['integration'] : array();
			foreach($files as $f => $type) {
				$file = $location.'/integration/webserver'.$f;
				if(file_exists($file)) {
					if(!is_readable($file)) {
						throw new Exception(sprintf(_("Certificate %s is not readable! Can not continue!"),$file));
					}
					$details['integration']['files'][$type] = $file;
					$details['integration']['hashes'][$type] = sha1_file($file);
				}
			}
			$file = $location.'/integration/certificate.pem';
			if(file_exists($file)) {
				if(!is_readable($file)) {
					throw new Exception(sprintf(_("Certificate %s is not readable! Can not continue!"),$file));
				}
				$details['integration']['files']['pem'] = $file;
				$details['integration']['hashes']['pem'] = sha1_file($file);
			}
		}
		if(!empty($details['additional'])) {
			$tmp = @json_decode($details['additional'],true);
			$details['additional'] = !empty($tmp) && is_array($tmp) ? $tmp : array();
		} else {
			$details['additional'] = array();
		}

		// Make sure that additional ALWAYS has an 'email' attribute, even if it's blank
		if (!isset($details['additional']['email'])) {
			$details['additional']['email'] = "";
		}

		return $details;
	}

	public function ajaxRequest($req, &$setting) {
		switch ($req) {
			case 'makeDefault':
			case 'getJSON':
				return true;
			break;
		}
		return false;
	}
	public function ajaxHandler(){
		if('makeDefault' == $_REQUEST['command']){
			$res = $this->makeCertDefault($_POST['id']);
			return array("status" => $res, "message" => "");
		}
		if('getJSON' == $_REQUEST['command'] && 'grid' == $_REQUEST['jdata']){
			return $this->getAllManagedCertificates();
		}
		return false;
	}

	/**
	 * Get FirewallAPI Object
	 *
	 * @return FirewallAPI
	 */
	public function getFirewallAPI() {
		static $api = false;
		if (!$api) {
			if (!class_exists('FirewallAPI')) {
				include __DIR__."/FirewallAPI.class.php";
			}
			$api = new Certman\FirewallAPI();
		}
		return $api;
	}

	/**
	 * Return a human readable expiration date
	 *
	 * This tries to use the 'humanReadable' function from FreePBX 14. If
	 * that is not available, a rough implementation is used instead.
	 * This will also return 'Expired!' if the date is in the past.
	 *
	 * @param timestamp int utime
	 */
	public function getReadableExpiration($timestamp = false) {
		if (!is_numeric($timestamp)) {
			return _("Unknown Expiration");
		}

		$ret = date('Y-m-d', $timestamp)." ";

		// How many seconds until it expires?
		$diff = $timestamp - time();

		// If $diff is negative, it means that the certificate has ALREADY expired.
		if ($diff < 0) {
			$ret .= "<strong>"._("Certificate Expired!")."</strong> ";
		}

		// humanDiff is not available in 13.
		$days = floor($diff/86400);
		$ret .= sprintf(_("(%s days)"), $days);

		return $ret;
	}

	function getPublicIP($host) {
		$ips = array();
		$queries = array(
			array('url' => 'https://dns.google/resolve?name=' . $host . '&type=1&do=1'),
			array('url' => 'https://cloudflare-dns.com/dns-query?name=' . $host . '&type=1&do=1'),
			array('url' => 'https://dns.quad9.net:5053/dns-query?name=' . $host . '&type=1&do=1'),
		);
		foreach($queries as $q) {
			$requests = \FreePBX::Curl()->requests($q['url']);
			$options = array(
				'timeout' => 2,
			);
			$headers = array(
				'Accept' => 'application/dns-json', //only needed for quad9, add headers to queries?
			);
			try {
				$response = $requests->get('', $headers, $options);
			} catch(\Exception $e) { continue; }

			$decoded = json_decode($response->body, 1);
			if (!empty($decoded['Answer']) && isset($decoded['Status']) && $decoded['Status'] == 0) {
				foreach($decoded['Answer'] as $a) {
					if($a['type'] == 1)  $ips[] = $a['data'];
				}
				break;
			}
		}
		return $ips;
	}
	
	/**
	 * uploadSSLCertificate
	 *
	 * @param  mixed $input
	 * @return void
	 */
	public function uploadSSLCertificate($input){
		$name = basename($input['name']);
		if($this->checkCertificateName($name)) {
			return array('status' => false, 'message' => _('Certificate name is already in use'));
		}
		$removeCSR = false;
		if(empty($input['privateKey']) && !empty($input['CSRReference'])) {
			$csr = $this->getCSRDetails($input['CSRReference']);
				if(empty($csr['files']['key'])) {
					$this->removeCSR();
					return array('status' => false, 'message' => _('No Private key to reference. Try generating a CSR first.'));
			}
			$pkey = file_get_contents($csr['files']['key']);
			$removeCSR = true;
		} elseif(!empty($input['privateKey'])) {
			$pkey = $input['privateKey'];
		} else {
			return array('status' => false, 'message' => _('No Private key to reference. Try generating a CSR first.'));
		}

		try {
			$this->importCertificate($name,$pkey,$input['signedCertificate'],$input['trustedChain'],$input['passPhrase']);
			$cid = $this->saveCertificate(null,$name,$input['description'],'up');
			if($input['default'] == true){
				$this->makeCertDefault($cid);
			}
		} catch(Exception $e) {
			return array('status' => false, 'message' => sprintf(_('There was an error importing the certificate: %s'),$e->getMessage()));
		}
		if($removeCSR) {
			$this->removeCSR(true);
		}
		return array('status' => true, 'message' => _('Added new certificate'));
	}


	public function runHook($hookname, $params = false) {
		// Runs a new style Syadmin hook
		if (!file_exists("/etc/incron.d/sysadmin")) {
			throw new \Exception("Sysadmin RPM not up to date");
		}

		$basedir = "/var/spool/asterisk/incron";
		if (!is_dir($basedir)) {
			throw new \Exception("$basedir is not a directory");
		}

		// Does our hook actually exist?
		if (!file_exists(__DIR__."/hooks/$hookname")) {
			throw new \Exception("Hook $hookname doesn't exist");
		}

		// Cool. So I want to run this hook..
		$filename = "$basedir/certman.$hookname";

		// Do I have any params?
		if ($params) {
			// Oh. I do. If it's an array, json encode and base64
			if (is_array($params)) {
				$b = base64_encode(gzcompress(json_encode($params)));
				// Note we derp the base64, changing / to _, because filepath.
				$filename .= ".".str_replace('/', '_', $b);
			} else {
				// Cast it to a string if it's anything else, and then make sure
				// it doesn't have any spaces.
				$filename .= ".".preg_replace("/[[:blank:]]+/", "", (string) $params);
			}
		}

		// Make sure it doesn't exist, if it was left hanging around
		// for some reason
		@unlink($filename);

		$fh = fopen($filename, "w+");
		if ($fh === false) {
			// WTF, unable to create file?
			return false;
		}

		// Now incron does its thing.
		fclose($fh);

		// Wait .5 of a second, make sure it's been deleted.
		usleep(500000);
		if (!file_exists($filename)) {
			return true;
		}
		// Odd. It should be gone. Something went wrong.
		return false;
	}

	function addAutoUpdateCron() {

		//check if update certificate cron exists, add if not
		$cronexists = false;
		foreach($this->FreePBX->Cron()->getAll() as $cron) {
			$str = "fwconsole certificates updateall -q";
			if (preg_match("/".$str."/i",$cron,$matches)) {
				$cronexists = true;
			}
			$str = "fwconsole certificates --updateall -q";
			if (preg_match("/".$str."/i",$cron,$matches)) {
				$cronexists = true;
			}
		}
		if(!$cronexists) {
			$ampsbin = $this->FreePBX->Config->get("AMPSBIN") ?? '/usr/sbin/';
			$this->FreePBX->Cron()->add(array(
				"command" => $ampsbin."/fwconsole certificates --updateall -q 2>&1 >/dev/null",
				"hour" => rand(0,3),
				"minute" => rand(0,59),
			));
		}
	}

	/**
	 * Reload HAProxy service if it's enabled to pick up renewed certificates.
	 * 
	 * This method checks if the sysadmin module is available and HAProxy is enabled,
	 * then triggers the appropriate hook to reload HAProxy with the new certificate.
	 */
	private function reloadHAProxyIfEnabled() {
		if (!$this->FreePBX->Modules->checkStatus("sysadmin")) {
			return;
		}

		try {
			$sysadmin = $this->FreePBX->Sysadmin;
			$haproxyEnabled = $sysadmin->getConfig("enableHaproxy");
			dbug("reloadHAProxyIfEnabled: HAProxy is enabled: " . $haproxyEnabled);
			if ($haproxyEnabled === 'enabled') {
				// Trigger the sysadmin hook to restart HAProxy with new certificate
				$sysadmin->runHook("update-sslconf", ['restart_haproxy' => true]);
				dbug("Certificate Manager: HAProxy reloaded after Let's Encrypt certificate renewal");
			}
		} catch (Exception $e) {
			dbug("Certificate Manager: Failed to reload HAProxy after certificate renewal: " . $e->getMessage());
		}
	}
}
