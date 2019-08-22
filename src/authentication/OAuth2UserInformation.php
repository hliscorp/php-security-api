<?php
namespace Lucinda\WebSecurity;

/**
 * Encapsulates abstract information about remote logged in user on OAuth2 provider.
 */
interface OAuth2UserInformation
{
    /**
     * Gets remote user id.
     *
     * @return integer
     */
    public function getId();
    
    /**
     * Gets remote user name.
     *
     * @return string
     */
    public function getName();
    
    /**
     * Gets remote user email.
     *
     * @return string
     */
    public function getEmail();
}
