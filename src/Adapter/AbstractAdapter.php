<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter;

use InvalidArgumentException;

abstract class AbstractAdapter implements AdapterInterface
{
    /**
     * Identity.
     *
     * @var string
     */
    protected $identifier;

    /**
     * attribute map.
     *
     * @var iterable
     */
    protected $map = [];

    /**
     * Identity attribute.
     *
     * @var string
     */
    protected $identity_attribute = 'uid';

    /**
     * Set options.
     *
     * @param iterable $config
     */
    public function setOptions(? Iterable $config = null): AdapterInterface
    {
        if (null === $config) {
            return $this;
        }

        foreach ($config as $option => $value) {
            switch ($option) {
                case 'map':
                    $this->map = $value;

                break;
                case 'identity_attribute':
                    $this->identity_attribute = $value;

                break;
                default:
                    throw new InvalidArgumentException('unknown option '.$option.' given');
            }
        }

        return $this;
    }

    /**
     * Get identifier.
     */
    public function getIdentityAttribute(): string
    {
        return $this->identity_attribute;
    }

    /**
     * Get attribute map.
     */
    public function getAttributeMap(): Iterable
    {
        return $this->map;
    }
}
