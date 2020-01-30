<?php

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\shib2idpnameid\Auth\Process\PersistentNameID;

class PersistentNameIDTest extends TestCase
{

    public function testPersistentNameID() {
        $config = [
          'attribute' => 'uid'
        ];
        $proc = new PersistentNameID($config, null);

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

        $proc->process($state);

        $this->assertArrayHasKey('eduPersonTargetedID', $state['Attributes']);
        $expectedValue = '<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="https://idp.example.edu/shibboleth" SPNameQualifier="https://somesp.edugain.example.edu/sp" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">D+oyFgppbxIm1ojPsqrhpyW8Gdg=</saml:NameID>';
        $this->assertEquals($expectedValue, $state['Attributes']['eduPersonTargetedID'][0]);
    }

}