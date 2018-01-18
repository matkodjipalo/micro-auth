<?php

declare(strict_types=1);

/**
 * balloon
 *
 * @copyright   Copryright (c) 2012-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     GPL-3.0 https://opensource.org/licenses/GPL-3.0
 */

namespace Micro\Auth\Adapter;

use Micro\Auth\Exception;
use Psr\Log\LoggerInterface as Logger;

abstract class AbstractAdapter implements AdapterInterface
{
    /**
     * Identity.
     *
     * @var string
     */
    protected $identifier;

    /**
     * attribute sync cache.
     *
     * @var int
     */
    protected $attr_sync_cache = 0;

    /**
     * attribute map.
     *
     * @var iterable
     */
    protected $map = [];

    /**
     * Logger.
     *
     * @var Logger
     */
    protected $logger;

    /**
     * Get attribute sync cache.
     *
     * @return int
     */
    public function getAttributeSyncCache(): int
    {
        return $this->attr_sync_cache;
    }

    /**
     * Set options.
     *
     * @param iterable $config
     *
     * @return AdapterInterface
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
                case 'attr_sync_cache':
                    $this->attr_sync_cache = (int) $value;

                break;
                default:
                    throw new Exception('unknown option '.$option.' given');
            }
        }

        return $this;
    }

    /**
     * Get identifier.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * Get attribute map.
     *
     * @return iterable
     */
    public function getAttributeMap(): Iterable
    {
        return $this->map;
    }
}
