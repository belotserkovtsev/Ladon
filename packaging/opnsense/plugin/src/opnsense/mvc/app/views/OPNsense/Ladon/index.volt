<script>
    $(document).ready(function() {
        function toggleRemote() {
            var ec = $("#ladon\\.general\\.probe_mode").val() === 'exit-compare';
            $('tr[id="row_ladon.general.remote_url"]').toggleClass('hidden', !ec);
            $('tr[id="row_ladon.general.remote_auth"]').toggleClass('hidden', !ec);
        }

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/ladon/settings/set", 'frm_GeneralSettings', function() {
                    dfObj.resolve();
                });
                return dfObj;
            }
        });

        mapDataToFormUI({'frm_GeneralSettings': "/api/ladon/settings/get"}).done(function() {
            $('.selectpicker').selectpicker('refresh');
            toggleRemote();
            updateServiceControlUI('ladon');
        });

        $("#ladon\\.general\\.probe_mode").change(toggleRemote);
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_GeneralSettings']) }}
</div>

{{ partial("layout_partials/base_apply_button", {'data_endpoint': '/api/ladon/service/reconfigure', 'data_service_widget': 'ladon'}) }}
