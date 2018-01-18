<?php

declare(strict_types=1);

/**
 * balloon
 *
 * @copyright   Copryright (c) 2012-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     GPL-3.0 https://opensource.org/licenses/GPL-3.0
 */

namespace Micro\Auth;

use Micro\Auth\Adapter\AdapterInterface;
use Psr\Log\LoggerInterface as Logger;

class Identity implements IdentityInterface
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
    protected $attribute_map;

    /**
     * Auth adapter.
     *
     * @var AdapterInterface
     */
    protected $adapter;

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
     * {@inheritDoc}
     */
    public function getAttributeMap(): AttributeMapInterface
    {
        return $this->attribute_map;
    }

    /**
     * {@inheritDoc}
     */
    public function getAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    /**
     * {@inheritDoc}
     */
    public function getIdentifier(): string
    {
        return $this->adapter->getIdentifier();
    }

    /**
     * {@inheritDoc}
     */
    public function getAttributes(): array
    {
        return $this->attribute_map->map($this->adapter->getAttributes());
    }
}
