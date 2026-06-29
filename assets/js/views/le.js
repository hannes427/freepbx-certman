$(function () {
    let credentialId = 0;
    function enableDns() {
        $('#dnsprovidercontainer').html(`
            				<input type="text" class="form-control" id="dnsprovider" name="dnsprovider" value="${dns_provider}">
        `);
    }

    $(document).on('change', '#challengetype', function () {
        if ($(this).val() === 'dns01') {

            $('#dnssettings').show();
            enableDns();
            let input = document.getElementById("dnsprovider");
            input.setAttribute('required', 'required');
            input.setAttribute('pattern', '^dns_[a-z0-9]{2,}$');
        } else {
            $('#dnsprovidercontainer').empty();
            $('#credentialscontainer').empty();
            $('#dnssettings').hide();
        }
    });

    $(document).on('click', '#addDnsCredential', function () {
        credentialId++;
        $('#credentialscontainer').append(`
            <div class="element-container dns-row" data-id="${credentialId}">
                <div class="row">
                    <div class="form-group form-horizontal">
						<div class="col-md-3">
                            &nbsp;
						</div>
                        <div class="col-md-3">
                            <input type="text" class="form-control" id="dnsKeys[${credentialId}]" name="dnsKeys[${credentialId}]" placeholder="Key" required pattern="^[A-Za-z][A-Za-z0-9_]{1,63}$">
                        </div>
                        <div class="col-md-4">
                            <input type="password" class="form-control" name="dnsValues[${credentialId}]" placeholder="Value">
                        </div>
                        <div class="col-md-2">
                            <i class="fa-solid fa-trash-can removeDns"></i>
                        </div>
                    </div>
                </div>
            </div>
        `);
    });

    $(document).on('click', '.removeDns', function () {
        $(this).closest('.dns-row').remove();
    });
});