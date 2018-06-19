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

class Identity implements IdentityInterface
{
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
     * Identity.
     *
     * @var string
     */
    protected $identity;

    /**
     * Initialize.
     */
    public function __construct(AdapterInterface $adapter, string $identity, AttributeMap $map)
    {
        $this->identity = $identity;
        $this->attribute_map = $map;
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
        return $this->identity;
    }

    /**
     * {@inheritdoc}
     */
    public function getAttributes(): array
    {
        return $this->attribute_map->map($this->adapter->getAttributes($this));
    }
}
