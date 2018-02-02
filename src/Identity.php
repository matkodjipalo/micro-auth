<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
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
     * {@inheritdoc}
     */
    public function getAttributeMap(): AttributeMapInterface
    {
        return $this->attribute_map;
    }

    /**
     * {@inheritdoc}
     */
    public function getAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier(): string
    {
        return $this->adapter->getIdentifier();
    }

    /**
     * {@inheritdoc}
     */
    public function getAttributes(): array
    {
        return $this->attribute_map->map($this->adapter->getAttributes());
    }
}
