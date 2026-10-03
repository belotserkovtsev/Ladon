<script>
    $(document).ready(function() {

        function esc(s) { return $('<div>').text(s == null ? '' : s).html(); }

        function loadDoctor() {
            ajaxGet('/api/ladon/diagnostics/doctor', {}, function(data) {
                var r = data['response'];
                if (!r) { $('#doctor-body').html('<tr><td colspan="4">no data</td></tr>'); return; }
                var cls = (r.Exit === 0) ? 'success' : (r.Exit === 2 ? 'danger' : 'warning');
                // r.Exit/r.Verdict are 0/1/2; key the word off Exit (Verdict===0 is
                // JS-falsy, which is why the raw value showed "1"/"2"/"exit 0").
                var verdict = (r.Exit === 0) ? 'здоров' : (r.Exit === 2 ? 'сломан' : 'есть замечания');
                $('#doctor-banner').attr('class', 'alert alert-' + cls)
                    .text(verdict + '  (ladon ' + (r.Version || '') + ')');
                var rows = '';
                (r.Checks || []).forEach(function(c) {
                    var g = c.Status === 0 ? '<span class="fa fa-check text-success"></span>'
                          : c.Status === 2 ? '<span class="fa fa-times text-danger"></span>'
                          : '<span class="fa fa-exclamation-triangle text-warning"></span>';
                    rows += '<tr><td>' + esc(c.Stage) + '</td><td>' + g + '</td><td>' + esc(c.Title) +
                            (c.Detail ? '<br><small class="text-muted">' + esc(c.Detail) + '</small>' : '') +
                            '</td><td>' + (c.Fix ? '<code>' + esc(c.Fix) + '</code>' : '') + '</td></tr>';
                });
                $('#doctor-body').html(rows || '<tr><td colspan="4">—</td></tr>');
            });
        }

        function loadHot() {
            ajaxGet('/api/ladon/diagnostics/hot', {}, function(data) {
                var arr = data['response'] || [];
                $('#hot-count').text(arr.length);
                $('#hot-body').html(arr.length
                    ? arr.map(function(d) { return '<tr><td>' + esc(d) + '</td></tr>'; }).join('')
                    : '<tr><td>—</td></tr>');
            });
        }

        function loadRecent() {
            ajaxGet('/api/ladon/diagnostics/recent', {}, function(data) {
                var arr = data['response'] || [];
                $('#recent-body').html(arr.length
                    ? arr.map(function(d) {
                        return '<tr><td>' + esc(d.domain) + '</td><td>' + esc(d.state) +
                               '</td><td>' + esc(d.hits) + '</td><td>' + esc(d.last_seen) + '</td></tr>';
                    }).join('')
                    : '<tr><td colspan="4">—</td></tr>');
            });
        }

        function loadWhy() {
            var dom = $('#why-input').val();
            $('#why-out').text('…');
            ajaxGet('/api/ladon/diagnostics/why', { 'domain': dom }, function(data) {
                $('#why-out').text(data['response'] || '(no data)');
            });
        }

        $('#doctor-refresh').click(loadDoctor);
        $('#hot-refresh').click(loadHot);
        $('#recent-refresh').click(loadRecent);
        $('#why-btn').click(loadWhy);
        $('#why-input').keypress(function(e) { if (e.which === 13) { loadWhy(); } });

        loadDoctor();
        loadHot();
        loadRecent();
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#health">{{ lang._('Health') }}</a></li>
    <li><a data-toggle="tab" href="#hot">{{ lang._('Tunneled now') }}</a></li>
    <li><a data-toggle="tab" href="#recent">{{ lang._('Recent domains') }}</a></li>
    <li><a data-toggle="tab" href="#why">{{ lang._('Why a domain?') }}</a></li>
</ul>
<div class="tab-content content-box">
    <div id="health" class="tab-pane fade in active">
        <div style="padding: 12px;">
            <div id="doctor-banner" class="alert alert-info">…</div>
            <p><span id="doctor-refresh" class="fa fa-refresh" style="cursor: pointer;"></span>
               {{ lang._('refresh') }}</p>
            <table class="table table-striped">
                <thead><tr>
                    <th>{{ lang._('Stage') }}</th><th></th>
                    <th>{{ lang._('Check') }}</th><th>{{ lang._('Fix') }}</th>
                </tr></thead>
                <tbody id="doctor-body"></tbody>
            </table>
        </div>
    </div>
    <div id="hot" class="tab-pane fade">
        <div style="padding: 12px;">
            <p><span id="hot-refresh" class="fa fa-refresh" style="cursor: pointer;"></span>
               <b>{{ lang._('Tunneled now') }}</b> (<span id="hot-count">0</span>)</p>
            <table class="table table-striped">
                <thead><tr><th>{{ lang._('Domain') }}</th></tr></thead>
                <tbody id="hot-body"></tbody>
            </table>
        </div>
    </div>
    <div id="recent" class="tab-pane fade">
        <div style="padding: 12px;">
            <p><span id="recent-refresh" class="fa fa-refresh" style="cursor: pointer;"></span>
               {{ lang._('refresh') }}</p>
            <table class="table table-striped">
                <thead><tr>
                    <th>{{ lang._('Domain') }}</th><th>{{ lang._('State') }}</th>
                    <th>{{ lang._('Hits') }}</th><th>{{ lang._('Last seen') }}</th>
                </tr></thead>
                <tbody id="recent-body"></tbody>
            </table>
        </div>
    </div>
    <div id="why" class="tab-pane fade">
        <div style="padding: 12px;">
            <div class="input-group" style="max-width: 480px;">
                <input id="why-input" type="text" class="form-control" placeholder="example.com"/>
                <span class="input-group-btn">
                    <button id="why-btn" class="btn btn-default" type="button">{{ lang._('Explain') }}</button>
                </span>
            </div>
            <pre id="why-out" style="margin-top: 12px;"></pre>
        </div>
    </div>
</div>
