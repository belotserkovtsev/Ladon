<?php

namespace OPNsense\Ladon\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'ladon';
    protected static $internalModelClass = 'OPNsense\Ladon\Ladon';
}
