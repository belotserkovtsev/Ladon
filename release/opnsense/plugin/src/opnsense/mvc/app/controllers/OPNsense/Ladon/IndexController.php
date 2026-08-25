<?php

namespace OPNsense\Ladon;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->pick('OPNsense/Ladon/index');
    }

    public function settingsAction()
    {
        $this->indexAction();
    }

    public function diagnosticsAction()
    {
        $this->view->pick('OPNsense/Ladon/diagnostics');
    }
}
