<?php

namespace OPNsense\Ladon\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Ladon\Ladon';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'ladon';

    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            // reconfigure.sh exits non-zero (configd returns "Error (…)" instead of
            // "OK") when the Unbound dynlib fails to build — surface that as a failed
            // Apply, else the operator runs blind with DNS observation silently off.
            $out = trim((string)(new Backend())->configdRun('ladon reconfigure'));
            if ($out === 'OK') {
                return ['status' => 'ok'];
            }
            return ['status' => 'failed', 'message' => $out];
        }
        return ['status' => 'failed'];
    }
}
