<?php

use PHPUnit\Framework\TestCase;
use SAML2\Constants;
use SimpleSAML\Module\shib2idpnameid\Auth\Process\PersistentNameID;
use SimpleSAML\Module\shib2idpnameid\Auth\Process\PersistentNameID2TargetedID;

class PersistentNameIDTest extends TestCase
{

    public function testPersistentNameID() {
        $config = [
          'attribute' => 'uid'
        ];
        $proc = new PersistentNameID2TargetedID($config, null);

        $state = [
            'Attributes' => [
                'uid' => ['774333']
            ],
            'Destination' =>
                [
                    'entityid' => 'https://somesp.edugain.example.edu/sp'
                ],
            'Source' =>
                [
                    'entityid' => 'https://idp.example.edu/shibboleth'
                ]
        ];

        $standardPersistentAuthProc = new \SimpleSAML\Module\saml\Auth\Process\PersistentNameID($config, null);

        // set a name ID to use in our test
        $standardPersistentAuthProc->process($state);
        $this->assertArrayHasKey(Constants::NAMEID_PERSISTENT, $state['saml:NameID']);

        $proc->process($state);

        $expectedValue = new \SAML2\XML\saml\NameID();
        $expectedValue->setFormat('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
        $expectedValue->setValue('fed3500b21a7f41a0c29f6e361b31794bb185b10');
        $this->assertEquals($expectedValue, $state['Attributes']['uid'][0]);
    }

}