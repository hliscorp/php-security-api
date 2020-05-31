<?php
namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Encapsulates logout request data. Inner class of FormRequestValidator!
 */
class LogoutRequest
{
    private $sourcePage;
    private $targetPage;
    
    /**
     * Sets current page.
     *
     * @param string $sourcePage
     */
    public function setSourcePage(string $sourcePage): void
    {
        $this->sourcePage= $sourcePage;
    }
    
    /**
     * Sets page to redirect to on login/logout success/failure.
     *
     * @param string $targetPage
     */
    public function setDestinationPage(string $targetPage): void
    {
        $this->targetPage= $targetPage;
    }
    
    /**
     * Gets current page.
     *
     * @return string
     */
    public function getSourcePage(): string
    {
        return $this->sourcePage;
    }
    
    /**
     * Gets page to redirect to on login/logout success/failure.
     *
     * @return string
     */
    public function getDestinationPage(): string
    {
        return $this->targetPage;
    }
}
