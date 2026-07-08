<script>
let dns_provider = '<?= $cert['additional']['dnsprovider'] ?? '' ?>';
</script>
<script src='modules/certman/assets/js/views/le.js'></script>
<?php
if(!empty($acmeMessage)) {
	$acmeMessageHtml = '<div class="alert alert-' . $acmeMessage['type'] .'">'. $acmeMessage['message'] . '</div>';
}
if(!empty($message)) {
	$messagehtml = '<div class="alert alert-' . $message['type'] .'">'. $message['message'] . '</div>';
}

$alert = "<div class='alert alert-info'><h3>"._("Important")."</h3>";
$alert .= "<p>"._("When using the HTTP challenge, Let's Encrypt certificate creation and validation requires unrestricted inbound HTTP access on port 80 to the Let's Encrypt token directories.")." </p>";
$alert .= "<p>"._("If security is managed by the PBX Firewall module, this process should be automatic. Alternate security methods and external firewalls will require manual configuration.")." </p>";
$alert .= "<p>"._("For more information see: ")."<a href='https://wiki.sangoma.com/display/FPG/Certificate+Management+User+Guide' target='_blank'>https://wiki.sangoma.com/display/FPG/Certificate+Management+User+Guide</a> </p>";
$alert .= "<p>"._("When using the DNS challenge, no modifications to the firewall configuration are necessary.")." </p>";
$alert .= "</div>";
?>

<div class="container-fluid">
	<h1><?php echo !empty($cert['cid']) ? _("Edit Let's Encrypt Certificate") : _("New Let's Encrypt Certificate")?></h1>
	<?php echo !empty($acmeMessageHtml) ? $acmeMessageHtml : "" ?>
	<?php echo !empty($messagehtml) ? $messagehtml : "" ?>
	<div class='alert alert-info'><?php echo $alert; printf(_("Let's Encrypt Certificates are <strong>automatically</strong> updated either by %s or by acme.sh when required (Approximately every 2 months). Do not install your own certificate updaters!"), \FreePBX::Config()->get("DASHBOARD_FREEPBX_BRAND")); ?></div>
	<div class = "display full-border">
		<div class="row">
			<div class="col-sm-12">
				<div class="fpbx-container">
					<div class="display full-border" id='certpage'>
						<form class="fpbx-submit" name="frm_certman" action="config.php?display=certman" method="post" enctype="multipart/form-data" data-fpbx-delete="config.php?display=certman&amp;certaction=delete&amp;type=cert&amp;id=<?php echo $cert['cid'] ?? "" ?>">
							<input id="certaction" type="hidden" name="certaction" value="<?php echo !empty($cert['cid']) ? 'edit' : 'add'?>">
							<input id="certtype" type="hidden" name="type" value="le">
							<input id="cid" type="hidden" name="cid" value="<?php echo !empty($cert['cid']) ? $cert['cid'] : ''?>">

							<!-- Begin Section -->
							<div class="section-title" data-for="edit-cert">
								<h3>
									<i class="fa fa-minus"></i>
									<?php echo !empty($cert['cid']) ? _("Edit Certificate") : _("New Certificate")?>
								</h3>
							</div>
							<div class="section" data-id="edit-cert">
								<!-- Hostname -->
								<div class="element-container">
									<div class="row">
										<div class="form-group form-horizontal">
											<div class="col-md-3">
												<label class="control-label" for="host"><?php echo _("Certificate Host Name")?></label>
												<i class="fa fa-question-circle fpbx-help-icon" data-for="host"></i>
											</div>
											<div class="col-md-9">
												<?php if (empty($cert['cid'])) { ?>
													<input type="text" class="form-control" id="host" name="host" placeholder="server.example.com" required value="<?php echo $hostname?>">
												<?php } else { ?>
													<?php echo !empty($cert['basename']) ? $cert['basename'] : ""?>
												<?php } ?>
											</div>
										</div>
										<div class="col-md-12">
											<span id="host-help" class="help-block fpbx-help-block" style=""><?php echo _("This must be the hostname you are requesting a certificate for. LetsEncrypt will validate that the hostname resolves to this machine, and attempt to connect to it.")?></span>
										</div>
									</div>
								</div>
								<!-- END Hostname -->

								<!-- eMail -->
								<div class="element-container">
									<div class="row">
										<div class="form-group form-horizontal">
											<div class="col-md-3">
												<label class="control-label" for="email"><?php echo _("ACME account Email")?></label>
												<i class="fa fa-question-circle fpbx-help-icon" data-for="email"></i>
											</div>
											<div class="col-md-9">
												<?php echo $settings['acmeEmail'] ?? ""; ?>
											</div>
										</div>
										<div class="col-md-12">
											<span id="email-help" class="help-block fpbx-help-block" style=""><?php echo _("The email address is managed at account level. Please use the ACME settings page to update it.")?></span>
										</div>
									</div>
								</div>
								<!-- END eMail -->

								<!-- Alternative Names -->
								<div class="element-container">
									<div class="row">
										<div class="form-group form-horizontal">
											<div class="col-md-3">
												<label class="control-label" for="SAN"><?php echo _("Alternative Names"); ?></label>
												<i class="fa fa-question-circle fpbx-help-icon" data-for="SAN"></i>
											</div>
											<div class="col-md-9">
												<textarea id="SAN" name="SAN" class="form-control" cols=50 rows=2><?php echo isset($cert['additional']['san'])?implode("\n",$cert['additional']['san']):"";?></textarea>
											</div>
										</div>
									</div>
									<div class="row">
										<div class="col-md-12">
											<span id="SAN-help" class="help-block fpbx-help-block"><?php echo _("List alternate Fully Qualified Domain Names for this certificate, one per line. Names must be resolvable by public DNS and point to this server.")?></span>
										</div>
									</div>
								</div>
								<!-- END Alternative Names -->

								<!-- Challenge Method -->
								<div class="element-container">
									<div class="row">
										<div class="form-group form-horizontal">
											<div class="col-md-3">
												<label class="control-label" for="challengetype"><?php echo _("Challenge Over")?></label>
												<i class="fa fa-question-circle fpbx-help-icon" data-for="challengetype"></i>
											</div>
											<div class="col-md-9">
												<select class="form-control" id="challengetype" name="challengetype">
                                                    <option value="http01" <?php echo !empty($cert['additional']['challengetype']) && $cert['additional']['challengetype'] == 'http01' ? 'selected': ''?>>HTTP</option>
                                                    <option value="dns01" <?php echo !empty($cert['additional']['challengetype']) && $cert['additional']['challengetype'] == 'dns01' ? 'selected': ''?>>DNS</option>
                                                </select>
											</div>
										</div>
										<div class="col-md-12">
											<span id="challengetype-help" class="help-block fpbx-help-block"><?php echo _("Choose how domain ownership should be validated for certificate issuance.<br>HTTP validation requires inbound access on port 80. DNS validation requires supported DNS API credentials.")?></span>
										</div>
									</div>
								</div>
								<!-- END Challenge Method -->

								<!-- DNS Settings (hidden by default) -->
								<div id="dnssettings" style="display: none;">
									<!-- DNS Provider -->
									 <div class="element-container">
										<div class="row">
											<div class="form-group form-horizontal">
												<div class="col-md-3">
													<label class="control-label" for="dnsprovider"><?php echo _("DNS Provider")?></label>
													<i class="fa fa-question-circle fpbx-help-icon" data-for="dnsprovider"></i>
												</div>
												<div class="col-md-9">
													<div id="dnsprovidercontainer"></div>
												</div>
											</div>
											<div class="col-md-12">
												<span id="dnsprovider-help" class="help-block fpbx-help-block"><?php echo _("Enter your DNS API provider.<br>See the official acme.sh <a href=\"https://github.com/acmesh-official/acme.sh/wiki/dnsapi\">wiki</a> for a list of supported providers and their required credential settings.")?></span>
											</div>
										</div>
									</div>
									<!-- END DNS Provider -->

									<!-- DNS API Credentials container -->
									<div id="credentialscontainer">
										<!-- DNS API Credentials -->
										<div class="element-container">
											<div class="row">
												<div class="form-group form-horizontal">
													<div class="col-md-3">
														<label class="control-label" for="dnsapi"><?php echo _("DNS API Credentials")?></label>
														<i class="fa fa-question-circle fpbx-help-icon" data-for="dnsapi"></i>
													</div>
													<div class="col-md-9">
														<?php if(!empty($cert['additional']['challengetype']) && $cert['additional']['challengetype'] === 'dns01' && !empty($cert['additional']['dnsprovider'])) { ?>
															<button type="button" class="btn btn-default" id="enableDnsEdit"><?php echo _("Edit DNS Credentials") ?></button>
														<?php } else { ?>
															<i id="addDnsCredential" class="fa fa-plus" style="cursor:pointer;"></i>
														<?php } ?>
													</div>
												</div>
												<div class="col-md-12">
													<span id="dnsapi-help" class="help-block fpbx-help-block"><?php echo _("Click the add button to add the required DNS API credentials as key-value pairs.")?></span>
												</div>
											</div>
										</div>
										<!-- END DNS API Credentials -->
									</div>
									<!-- END DNS API Credentials container -->
								</div>
								<!-- END DNS Settings -->
							</div>
							<!-- END Section -->

							<!-- Begin Section -->
							<?php if(!empty($cert['cid'])) { ?>
								<div class="section-title" data-for="show-cert">
									<h3>
										<i class="fa fa-minus"></i>
										<?php echo _("Issued Certificate Details") ?>
									</h3>
								</div>
								<div class="section" data-id="show-cert">
									<!-- Common Name -->
									<div class="element-container">
										<div class="row">
											<div class="form-group form-horizontal">
												<div class="col-md-3">
													<label class="control-label" for="cn"><?php echo _("Certificate Common Name")?></label>
												</div>
												<div class="col-md-9">
													<?php echo $certinfo['subject']['CN']?>
												</div>
											</div>
										</div>
									</div>
									<!-- END Common Name -->

									<!-- Expiration -->
									<div class="element-container">
										<div class="row">
											<div class="form-group form-horizontal">
												<div class="col-md-3">
													<label class="control-label" for="an"><?php echo _("Certificate Alternative Names")?></label>
												</div>
												<div class="col-md-9">
													<?php echo $certinfo['extensions']['subjectAltName']?>
												</div>
											</div>
										</div>
									</div>
									<!-- END Expiration -->

									<!-- Expiration -->
									<div class="element-container">
										<div class="row">
											<div class="form-group form-horizontal">
												<div class="col-md-3">
													<label class="control-label" for="expires"><?php echo _("Certificate Valid Until")?></label>
												</div>
												<div class="col-md-9"> <?php echo \FreePBX::Certman()->getReadableExpiration($certinfo['validTo_time_t']); ?> </div>
											</div>
										</div>
									</div>
									<!-- END Expiration -->

									<!-- Policies -->
									<div class="element-container">
										<div class="row">
											<div class="form-group form-horizontal">
												<div class="col-md-3">
													<label class="control-label" for="cp"><?php echo _("Certificate Policies")?></label>
													<i class="fa fa-question-circle fpbx-help-icon" data-for="cp"></i>
												</div>
												<div class="col-md-9">
													<textarea class="form-control" rows=3 readonly><?php echo $certinfo['extensions']['certificatePolicies']?></textarea>
												</div>
											</div>
											<div class="col-md-12">
												<span id="cp-help" class="help-block fpbx-help-block" style=""><?php echo _('A certificate policy (CP) is a document which aims to state what are the different actors of a public key infrastructure (PKI), their roles and their duties')?></span>
											</div>
										</div>
									</div>
									<!-- END Policies -->
								</div>
							<?php } ?>
							<!-- END Section -->
						</form>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
