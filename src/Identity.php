<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @author      Raffael Sahli <sahli@gyselroth.net>
 * @copyright   Copryright (c) 2015-2017 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth;

use Micro\Auth\Adapter\AdapterInterface;
use Psr\Log\LoggerInterface as Logger;

class Identity
{
    /**
     * Logger.
     *
     * @var Logger
     */
    protected $logger;
    /**
     * Attribute map.
     *
     * @var AttributeMap
     */
    private $attribute_map;

    /**
     * Auth adapter.
     *
     * @var AdapterInterface
     */
    private $adapter;

    /**
     * Initialize.
     *
     * @param AdapterInterface $adapter
     * @param AttributeMap     $map
     * @param Logger           $logger
     */
    public function __construct(AdapterInterface $adapter, AttributeMap $map, Logger $logger)
    {
        $this->attribute_map = $map;
        $this->logger = $logger;
        $this->adapter = $adapter;
    }

    /**
     * Get attribute map.
     *
     * @return AttributeMap
     */
    public function getAttributeMap(): AttributeMap
    {
        return $this->attribute_map;
    }

    /**
     * Get adapter.
     *
     * @return AdapterInterface
     */
    public function getAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    /**
     * Get identity.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->adapter->getIdentifier();
    }

    /**
     * Get identity attributes.
     *
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attribute_map->map($this->adapter->getAttributes());
    }
}
