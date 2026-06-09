<?php

function ladon_enabled()
{
    $mdl = new \OPNsense\Ladon\Ladon();
    return (string)$mdl->general->enabled == '1';
}

function ladon_services()
{
    $services = [];

    if (ladon_enabled()) {
        $services[] = [
            'description' => gettext('Ladon split-routing'),
            'configd' => [
                'restart' => ['ladon restart'],
                'start' => ['ladon start'],
                'stop' => ['ladon stop'],
            ],
            'name' => 'ladon',
            'pidfile' => '/var/run/ladon.pid',
        ];
    }

    return $services;
}
