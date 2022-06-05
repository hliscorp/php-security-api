<?php

namespace Test\Lucinda\WebSecurity\Authorization;

use Lucinda\WebSecurity\Authorization\DAOWrapper;
use Lucinda\WebSecurity\Request;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authorization\ResultStatus;

class DAOWrapperTest
{
    private $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string(
            '
<security>
    <authorization>
        <by_dao page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO" user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"/>
    </authorization>
</security>
'
        );
    }


    public function getResult()
    {
        $results = [];

        $request = new Request();
        $request->setMethod("GET");

        $request->setUri("asdf");
        $object = new DAOWrapper($this->xml, $request, null);
        $results[] = new Result($object->getResult()->getStatus()==ResultStatus::NOT_FOUND, "test path not found");

        $request->setUri("login");
        $object = new DAOWrapper($this->xml, $request, null);
        $results[] = new Result($object->getResult()->getStatus()==ResultStatus::OK, "guest allowed to login");

        $request->setUri("index");
        $object = new DAOWrapper($this->xml, $request, null);
        $results[] = new Result($object->getResult()->getStatus()==ResultStatus::UNAUTHORIZED, "guest unauthorized to index");

        $request->setUri("index");
        $object = new DAOWrapper($this->xml, $request, 1);
        $results[] = new Result($object->getResult()->getStatus()==ResultStatus::OK, "user allowed to index");

        $request->setUri("administration");
        $object = new DAOWrapper($this->xml, $request, 1);
        $results[] = new Result($object->getResult()->getStatus()==ResultStatus::FORBIDDEN, "user forbidden to administration");

        return $results;
    }
}
