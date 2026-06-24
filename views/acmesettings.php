<div class="container-fluid">
	<h1><?php echo _("ACME Settings") ?></h1>
	<div class = "display full-border">
		<div class="row">
			<div class="col-sm-12">
				<div class="fpbx-container">
					<div class="display full-border" id='acmepage'>
						<form class="fpbx-submit" name="frm_certman" action="config.php?display=certman" method="post" enctype="multipart/form-data">
							<input id="certaction" type="hidden" name="acmesettings" value="true">
							<!--ACME Binary-->
							<div class="element-container">
								<div class="row">
									<div class="col-md-12">
										<div class="row">
											<div class="form-group">
												<div class="col-md-3">
													<label class="control-label" for="acmeBinary"><?php echo _("Path to the acme.sh script")?></label>
													<i class="fa fa-question-circle fpbx-help-icon" data-for="acmeBinary"></i>
												</div>
												<div class="col-md-9">
													<input type="text" class="form-control" autocomplete="off" name="acmeBinary" id="acmeBinary" data-invalid="<?php echo _('This field cannot be blank and only letters, numbers, slash (/), dot (.), hyphen (-) and underscore (_) are allowed.')?>" value="<?php echo $acmeBinary ?>" required pattern="^\/[A-Za-z0-9\._\-\/]+\/acme\.sh$">
												</div>
											</div>
										</div>
									</div>
								</div>
								<div class="row">
									<div class="col-md-12">
										<span id="acmeBinary-help" class="help-block fpbx-help-block"><?php echo _("The full path to the installed acme.sh script. Only letters, numbers, slash (/), dot (.), hyphen (-) and underscore (_) are allowed.<br>Please ensure that acme.sh is installed and that the user running the web server (by default 'asterisk') has permission to execute the script. ")?></span>
									</div>
								</div>
							</div>
							<!--END ACME Binary-->
							<!--ACME Config Dir-->
							<div class="element-container">
								<div class="row">
									<div class="col-md-12">
										<div class="row">
											<div class="form-group">
												<div class="col-md-3">
													<label class="control-label" for="acmeConfDir"><?php echo _("Path to the Config directory")?></label>
													<i class="fa fa-question-circle fpbx-help-icon" data-for="acmeConfDir"></i>
												</div>
												<div class="col-md-9">
													<input type="text" class="form-control" autocomplete="off" name="acmeConfDir" id="acmeConfDir" data-invalid="<?php echo _('This field cannot be blank and only letters, numbers, slash (/), dot (.), hyphen (-) and underscore (_) are allowed.')?>" value="<?php echo $acmeConfDir ?>" required pattern="^\/[A-Za-z0-9\._\-\/]+$">
												</div>
											</div>
										</div>
									</div>
								</div>
								<div class="row">
									<div class="col-md-12">
										<span id="acmeConfDir-help" class="help-block fpbx-help-block"><?php echo _("Full path to the configuration directory. Only letters, numbers, slash (/), dot (.), hyphen (-) and underscore (_) are allowed.<br>Ensure that the web server user (default: 'asterisk') has write permissions for this directory.")?></span>
									</div>
								</div>
							</div>
							<!--END ACME Config Dir-->
							<!--ACME Account email-->
							<div class="element-container">
								<div class="row">
									<div class="col-md-12">
										<div class="row">
											<div class="form-group">
												<div class="col-md-3">
													<label class="control-label" for="acmeEmail"><?php echo _("Account eMail")?></label>
													<i class="fa fa-question-circle fpbx-help-icon" data-for="acmeEmail"></i>
												</div>
												<div class="col-md-9">
													<input type="text" class="form-control" autocomplete="off" name="acmeEmail" id="acmeEmail" data-invalid="<?php echo _('Only valid email addresses are allowed. Letters, numbers, and the characters . _ + - and @ are permitted.')?>" value="<?php echo $acmeEmail ?>" pattern="^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$">
												</div>
											</div>
										</div>
									</div>
								</div>
								<div class="row">
									<div class="col-md-12">
										<span id="acmeEmail-help" class="help-block fpbx-help-block"><?php echo _("Optional email address associated with the ACME account for notifications and recovery.")?></span>
									</div>
								</div>
							</div>
							<!--END ACME Account email--->
							<!--Update Method for the certificates-->
							<div class="element-container">
								<div class="row">
									<div class="col-md-12">
										<div class="row">
											<div class="form-group">
												<div class="col-md-3">
													<label class="control-label" for="acmeUpdateMethod"><?php echo _("Certificate Renew mechanism")?></label>
													<i class="fa fa-question-circle fpbx-help-icon" data-for="acmeUpdateMethod"></i>
												</div>
												<div class="col-md-9">
													<select class="form-control" id="acmeUpdateMethod" name="acmeUpdateMethod">
														<?php if (empty($acmeUpdateMethod)) { ?>
															<option value="" disabled selected><?php echo _("Please select")?></option>
														<?php } ?>
														<option value="cron" <?php echo ($acmeUpdateMethod === 'cron') ? 'selected' : '' ?>>System Cron</option>
														<option value="freepbx" <?php echo ($acmeUpdateMethod === 'freepbx') ? 'selected' : '' ?>>Managed by FreePBX</option>
													</select>
												</div>
											</div>
										</div>
									</div>
								</div>
								<div class="row">
									<div class="col-md-12">
										<span id="acmeUpdateMethod-help" class="help-block fpbx-help-block"><?php echo _("Choose how certificate renewal is scheduled: either by the operating system or by FreePBX.<br>Switching the method will automatically remove the previously configured renewal schedule.).")?></span>
									</div>
								</div>
							</div>
							<!--END Update Method for the certificates-->
						</form>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
