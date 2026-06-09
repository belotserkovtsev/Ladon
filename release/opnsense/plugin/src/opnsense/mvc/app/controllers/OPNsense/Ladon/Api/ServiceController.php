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
            (new Backend())->configdRun('ladon reconfigure');
            return ['status' => 'ok'];
        }
        return ['status' => 'failed'];
    }
}
